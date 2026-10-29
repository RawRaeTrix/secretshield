"""Repository scanning primitives for secrets, unsafe patterns and known CVEs.

SecretShield deliberately keeps matched secret values out of its results.  A
finding contains a redacted line of context, a path and a remediation hint.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import os
import re
import tomllib
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Any

MAX_FILE_BYTES = 3_000_000
MAX_TOTAL_BYTES = 512_000_000
MAX_FILES = 20_000
MAX_OSV_PACKAGES = 1_000
OSV_ENDPOINT = "https://api.osv.dev/v1/querybatch"

IGNORED_DIRS = {
    ".git", ".hg", ".svn", ".idea", ".next", ".nuxt", ".turbo",
    ".venv", "venv", "node_modules", "vendor", "dist", "build",
    "coverage", "__pycache__", ".mypy_cache", ".ruff_cache", ".tox",
    "target", "Pods", "DerivedData",
}
EXAMPLE_NAMES = {".env.example", ".env.sample", ".env.template", "sample.env", "example.env"}
CODE_SUFFIXES = {
    ".py", ".pyw", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".go", ".rb", ".php", ".java", ".kt", ".cs", ".cpp", ".c",
    ".h", ".hpp", ".rs", ".swift", ".sh", ".bash", ".zsh", ".ps1",
    ".tf", ".tfvars", ".yml", ".yaml", ".toml", ".ini", ".conf",
    ".properties", ".dockerfile",
}

SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("SECRET-AWS-ACCESS-KEY", "AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("SECRET-GITHUB-TOKEN", "GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{50,255})\b")),
    ("SECRET-SLACK-TOKEN", "Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("SECRET-STRIPE-KEY", "Stripe live secret key", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("SECRET-GOOGLE-API-KEY", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("SECRET-JWT", "JSON web token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b")),
    ("SECRET-PRIVATE-KEY", "Private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
]
GENERIC_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
    r"password|passwd|secret|private[_-]?key)\b\s*[:=]\s*"
    r"(['\"]?)([^\s,'\";}]{10,})"
)
PLACEHOLDER_WORDS = {
    "example", "sample", "changeme", "change-me", "replace-me", "placeholder",
    "your-token", "your-secret", "your-api-key", "password", "secret",
    "undefined", "null", "none", "false", "true", "process.env", "os.getenv",
}

CODE_RULES: list[tuple[str, str, str, str, re.Pattern[str]]] = [
    (
        "CODE-TLS-VERIFY-DISABLED", "TLS certificate checks are disabled", "high",
        "Certificate verification is disabled here. Restore verification, or configure a trusted CA bundle for this service.",
        re.compile(r"\bverify\s*=\s*False\b"),
    ),
    (
        "CODE-SHELL-TRUE", "Shell execution is enabled for a subprocess", "high",
        "Passing untrusted input through a shell can allow command injection. Prefer an argument list and leave shell execution disabled.",
        re.compile(r"\bsubprocess\.(?:run|Popen|call|check_output)\s*\([^\n)]*\bshell\s*=\s*True\b"),
    ),
    (
        "CODE-CORS-WILDCARD", "CORS allows every origin", "medium",
        "A wildcard origin lets any website make browser requests to this service. Limit access to the origins your app needs.",
        re.compile(r"\ballow_origins\s*=\s*\[[^\]]*['\"]\*['\"]", re.IGNORECASE),
    ),
    (
        "CODE-DEBUG-ENABLED", "Debug mode is enabled", "medium",
        "Debug mode can expose diagnostic details and should not be enabled in a production deployment.",
        re.compile(r"\bDEBUG\s*=\s*True\b"),
    ),
    (
        "CODE-DYNAMIC-EVAL", "Dynamic code execution is used", "low",
        "Review the value passed to eval or exec. Never evaluate content that can be influenced by a user or an external system.",
        re.compile(r"\b(?:eval|exec)\s*\("),
    ),
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    frequencies = {char: count / len(value) for char, count in Counter(value).items()}
    return -sum(probability * math.log2(probability) for probability in frequencies.values())


def _is_placeholder(value: str) -> bool:
    lowered = value.strip("'\"`[](){} ").lower()
    return (
        lowered in PLACEHOLDER_WORDS
        or lowered.startswith(("your_", "your-", "<your", "${", "{{"))
        or lowered.startswith(("os.getenv(", "os.environ", "os.urandom(", "process.env.", "env.get(", "getenv(", "settings.", "secrets."))
        or lowered.endswith(("_here", "-here", "_example", "-example"))
        or lowered.count("x") > len(lowered) * 0.75
    )


def _finding_id(rule_id: str, relative_path: str, line: int, salt: str = "") -> str:
    return hashlib.sha256(f"{rule_id}\0{relative_path}\0{line}\0{salt}".encode()).hexdigest()[:16]


def _make_finding(
    *, rule_id: str, title: str, severity: str, category: str, relative_path: str,
    line: int | None, description: str, recommendation: str, evidence: str = "",
    url: str | None = None, confidence: str = "high", salt: str = "",
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": _finding_id(rule_id, relative_path, line or 0, salt),
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "category": category,
        "file": relative_path.replace("\\", "/"),
        "line": line,
        "description": description,
        "recommendation": recommendation,
        "evidence": evidence[:240],
        "confidence": confidence,
    }
    if url:
        result["url"] = url
    return result


def _secret_candidates(lines: list[str], relative_path: str) -> list[dict[str, Any]]:
    if Path(relative_path).name.lower() in EXAMPLE_NAMES:
        return []

    candidates: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        for rule_id, label, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(line):
                candidates.append({
                    "rule_id": rule_id, "title": f"{label} may be exposed",
                    "line": line_number, "start": match.start(),
                    "recommendation": "Revoke or rotate this credential, then load it from a secret manager or an environment variable.",
                })

        for match in GENERIC_ASSIGNMENT.finditer(line):
            key, value = match.group(1), match.group(3).strip("'\"` ")
            if not _is_placeholder(value) and 10 <= len(value) <= 512 and _entropy(value) >= 3.1:
                candidates.append({
                    "rule_id": "SECRET-HARDCODED-CREDENTIAL",
                    "title": f"Possible hard-coded {key.replace('_', ' ').replace('-', ' ')}",
                    "line": line_number, "start": match.start(3),
                    "recommendation": "Rotate this value if it is active, then read it from an environment variable or secret manager.",
                })

    findings: list[dict[str, Any]] = []
    for candidate in candidates:
        line_number = candidate["line"]
        findings.append(_make_finding(
            rule_id=candidate["rule_id"], title=candidate["title"], severity="critical",
            category="secrets", relative_path=relative_path, line=line_number,
            description="A value that resembles a credential was found in repository content. SecretShield stores only redacted evidence.",
            recommendation=candidate["recommendation"], evidence="Secret match redacted.",
            salt=str(candidate["start"]),
        ))
    return findings


def _scan_code(lines: list[str], relative_path: str) -> list[dict[str, Any]]:
    if Path(relative_path).suffix.lower() not in CODE_SUFFIXES:
        return []
    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        for rule_id, title, severity, recommendation, pattern in CODE_RULES:
            if pattern.search(line):
                findings.append(_make_finding(
                    rule_id=rule_id, title=title, severity=severity, category="code",
                    relative_path=relative_path, line=line_number,
                    description=title + ". This can make the application easier to compromise if reachable in production.",
                    recommendation=recommendation, evidence="", confidence="medium",
                ))
    return findings


def _dependency(name: str, version: str, ecosystem: str, path: str, line: int | None = None) -> dict[str, Any] | None:
    version = version.strip()
    if ecosystem != "Go":
        version = version.lstrip("v")
    if not name or not version or version.startswith(("$", "*")):
        return None
    return {"name": name, "version": version, "ecosystem": ecosystem, "file": path, "line": line}


def _parse_requirements(text: str, path: str) -> list[dict[str, Any]]:
    found = []
    pattern = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*(?:===|==)\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)")
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.split("#", 1)[0].strip()
        match = pattern.match(stripped)
        if match:
            item = _dependency(match.group(1), match.group(2), "PyPI", path, line_number)
            if item:
                found.append(item)
    return found


def _parse_package_lock(data: dict[str, Any], path: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for package_path, metadata in packages.items():
            if not package_path or not isinstance(metadata, dict):
                continue
            marker = "node_modules/"
            if marker not in package_path:
                continue
            name = package_path.rsplit(marker, 1)[-1]
            item = _dependency(name, str(metadata.get("version", "")), "npm", path)
            if item:
                found.append(item)

    def visit(dependencies: Any) -> None:
        if not isinstance(dependencies, dict):
            return
        for name, metadata in dependencies.items():
            if not isinstance(metadata, dict):
                continue
            item = _dependency(name, str(metadata.get("version", "")), "npm", path)
            if item:
                found.append(item)
            visit(metadata.get("dependencies"))

    if not packages:
        visit(data.get("dependencies"))
    return found


def _parse_toml_dependencies(text: str, name: str, path: str) -> list[dict[str, Any]]:
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    found: list[dict[str, Any]] = []
    if name == "poetry.lock":
        for item in data.get("package", []):
            if isinstance(item, dict):
                dependency = _dependency(str(item.get("name", "")), str(item.get("version", "")), "PyPI", path)
                if dependency:
                    found.append(dependency)
    elif name == "Cargo.lock":
        for item in data.get("package", []):
            if isinstance(item, dict) and item.get("source", "").startswith("registry+"):
                dependency = _dependency(str(item.get("name", "")), str(item.get("version", "")), "crates.io", path)
                if dependency:
                    found.append(dependency)
    return found


def _parse_go_sum(text: str, path: str) -> list[dict[str, Any]]:
    found = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[1].endswith("/go.mod"):
            continue
        item = _dependency(parts[0], parts[1], "Go", path)
        if item:
            found.append(item)
    return found


def _parse_dependencies(path: Path, relative_path: str, text: str) -> list[dict[str, Any]]:
    name = path.name.lower()
    if name == "package-lock.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        return _parse_package_lock(data, relative_path) if isinstance(data, dict) else []
    if name in {"requirements.txt", "requirements-prod.txt", "requirements-dev.txt"} or (
        name.startswith("requirements-") and name.endswith(".txt")
    ):
        return _parse_requirements(text, relative_path)
    if name in {"poetry.lock", "cargo.lock"}:
        return _parse_toml_dependencies(text, name, relative_path)
    if name == "go.sum":
        return _parse_go_sum(text, relative_path)
    return []


def _cvss_severity(vulnerability: dict[str, Any]) -> str:
    database_severity = str((vulnerability.get("database_specific") or {}).get("severity", "")).lower()
    severity_aliases = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium", "low": "low", "info": "info"}
    if database_severity in severity_aliases:
        return severity_aliases[database_severity]
    ecosystem_severity = str((vulnerability.get("ecosystem_specific") or {}).get("severity", "")).lower()
    if ecosystem_severity in severity_aliases:
        return severity_aliases[ecosystem_severity]
    for severity in vulnerability.get("severity", []):
        score_text = str(severity.get("score", ""))
        match = re.fullmatch(r"CVSS:3\.[01]/(.+)", score_text)
        if match:
            metrics = dict(part.split(":", 1) for part in match.group(1).split("/") if ":" in part)
            values = {
                "AV": {"N": .85, "A": .62, "L": .55, "P": .2},
                "AC": {"L": .77, "H": .44},
                "UI": {"N": .85, "R": .62},
                "C": {"H": .56, "L": .22, "N": 0},
                "I": {"H": .56, "L": .22, "N": 0},
                "A": {"H": .56, "L": .22, "N": 0},
            }
            pr_values = {"U": {"N": .85, "L": .62, "H": .27}, "C": {"N": .85, "L": .68, "H": .5}}
            try:
                scope = metrics["S"]
                exploitability = 8.22 * values["AV"][metrics["AV"]] * values["AC"][metrics["AC"]] * pr_values[scope][metrics["PR"]] * values["UI"][metrics["UI"]]
                impact_sub = 1 - (1 - values["C"][metrics["C"]]) * (1 - values["I"][metrics["I"]]) * (1 - values["A"][metrics["A"]])
                impact = 6.42 * impact_sub if scope == "U" else 7.52 * (impact_sub - .029) - 3.25 * (impact_sub - .02) ** 15
                if impact <= 0:
                    score = 0.0
                else:
                    score = min(10.0, 1.08 * (impact + exploitability) if scope == "C" else impact + exploitability)
                    score = math.ceil((score - 1e-9) * 10) / 10
            except (KeyError, TypeError):
                continue
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            return "low"
    return "high"


def _fixed_versions(vulnerability: dict[str, Any], ecosystem: str, package_name: str) -> str:
    fixed: list[str] = []
    for affected in vulnerability.get("affected", []):
        package = affected.get("package", {})
        if package.get("name") != package_name or package.get("ecosystem") != ecosystem:
            continue
        for version_range in affected.get("ranges", []):
            for event in version_range.get("events", []):
                value = event.get("fixed")
                if value:
                    fixed.append(str(value))
    return ", ".join(dict.fromkeys(fixed))


def _query_osv(dependencies: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    if not dependencies:
        return [], []
    if len(dependencies) > MAX_OSV_PACKAGES:
        return [], [f"Dependency check skipped: this repository has {len(dependencies):,} locked packages; the per-scan limit is {MAX_OSV_PACKAGES:,}."]
    queries = [
        {"version": item["version"], "package": {"name": item["name"], "ecosystem": item["ecosystem"]}}
        for item in dependencies
    ]
    body = json.dumps({"queries": queries}).encode("utf-8")
    request = urllib.request.Request(
        OSV_ENDPOINT, data=body, headers={"Content-Type": "application/json", "User-Agent": "SecretShield/1.0"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            data = json.loads(response.read(8_000_000).decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as error:
        reason = getattr(error, "reason", error)
        return [], [f"Dependency check unavailable ({reason}). Secret and code checks still completed."]

    findings: list[dict[str, Any]] = []
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return [], ["Dependency check unavailable (the advisory service returned an unexpected response). Secret and code checks still completed."]
    results = data["results"]
    result_notes = [] if len(results) == len(dependencies) else ["Dependency check incomplete: OSV returned a different number of package results than requested."]
    for index, result in enumerate(results[: len(dependencies)]):
        if not isinstance(result, dict):
            continue
        package = dependencies[index]
        for vulnerability in result.get("vulns", []) or []:
            if not isinstance(vulnerability, dict):
                continue
            aliases = vulnerability.get("aliases", [])
            advisory_id = str(vulnerability.get("id") or "OSV-UNKNOWN")
            title = next((str(alias) for alias in aliases if str(alias).startswith("CVE-")), advisory_id)
            summary = str(vulnerability.get("summary") or vulnerability.get("details") or "A known advisory affects this resolved dependency.")
            summary = re.sub(r"\s+", " ", summary).strip()
            fixed = _fixed_versions(vulnerability, package["ecosystem"], package["name"])
            recommendation = f"Upgrade {package['name']} to a fixed version ({fixed})." if fixed else f"Review the advisory and upgrade {package['name']} to a supported, patched version."
            references = vulnerability.get("references", [])
            url = next((item.get("url") for item in references if isinstance(item, dict) and item.get("url", "").startswith("https://")), None)
            findings.append(_make_finding(
                rule_id=f"OSV-{advisory_id}", title=f"{package['name']} {package['version']} · {title}",
                severity=_cvss_severity(vulnerability), category="dependencies", relative_path=package["file"],
                line=package["line"], description=summary, recommendation=recommendation,
                evidence=f"{package['name']}@{package['version']} ({package['ecosystem']})", url=url,
                salt=package["name"] + "@" + package["version"],
            ))
    return findings, result_notes


def _read_ignore_patterns(root: Path) -> list[str]:
    ignore_file = root / ".secretshieldignore"
    if not ignore_file.is_file():
        return []
    try:
        return [line.strip().replace("\\", "/") for line in ignore_file.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")]
    except OSError:
        return []


def scan_repository(repository: str | os.PathLike[str], include_dependencies: bool = True) -> dict[str, Any]:
    """Scan a repository folder and return redacted, JSON-safe findings."""
    started = monotonic()
    root = Path(repository).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Repository folder does not exist or is not a directory: {root}")

    ignores = _read_ignore_patterns(root)
    findings: list[dict[str, Any]] = []
    dependencies: list[dict[str, Any]] = []
    notes: list[str] = []
    files_scanned = 0
    files_skipped = 0
    bytes_scanned = 0
    stopped_early = False

    def on_walk_error(error: OSError) -> None:
        notes.append(f"A folder could not be read: {error.filename or error}.")

    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False, onerror=on_walk_error):
        current_path = Path(current)
        kept_dirs = []
        for dirname in dirnames:
            candidate = current_path / dirname
            if dirname not in IGNORED_DIRS and not candidate.is_symlink():
                kept_dirs.append(dirname)
        dirnames[:] = kept_dirs

        for filename in filenames:
            file_path = current_path / filename
            if file_path.is_symlink() or not file_path.is_file():
                files_skipped += 1
                continue
            relative_path = file_path.relative_to(root).as_posix()
            if any(fnmatch.fnmatch(relative_path, pattern) for pattern in ignores):
                files_skipped += 1
                continue
            try:
                size = file_path.stat().st_size
                if size > MAX_FILE_BYTES:
                    files_skipped += 1
                    continue
                if bytes_scanned + size > MAX_TOTAL_BYTES:
                    stopped_early = True
                    notes.append(f"Scan stopped at the {MAX_TOTAL_BYTES // 1_000_000} MB total file-size safety limit.")
                    break
                raw = file_path.read_bytes()
            except OSError:
                files_skipped += 1
                continue
            if b"\0" in raw[:8192]:
                files_skipped += 1
                continue
            text = raw.decode("utf-8", errors="replace")
            bytes_scanned += len(raw)
            lines = text.splitlines()
            files_scanned += 1
            secret_findings = _secret_candidates(lines, relative_path)
            findings.extend(secret_findings)
            findings.extend(_scan_code(lines, relative_path))
            if include_dependencies:
                dependencies.extend(_parse_dependencies(file_path, relative_path, text))
            if files_scanned >= MAX_FILES:
                stopped_early = True
                notes.append(f"Scan stopped at the {MAX_FILES:,}-file safety limit.")
                break
        if stopped_early:
            break

    dependencies = list({
        (item["ecosystem"], item["name"], item["version"], item["file"], item["line"]): item
        for item in dependencies
    }.values())
    dependency_count = len(dependencies)
    dependency_check_status = "disabled" if not include_dependencies else "no_locked_dependencies"
    dependency_findings: list[dict[str, Any]] = []
    dependency_notes: list[str] = []
    if include_dependencies:
        if dependency_count > MAX_OSV_PACKAGES:
            dependency_check_status = "limit_exceeded"
            dependency_notes = [f"Dependency check skipped: this repository has {dependency_count:,} locked packages; the per-scan limit is {MAX_OSV_PACKAGES:,}."]
        elif dependency_count:
            dependency_findings, dependency_notes = _query_osv(dependencies)
            dependency_check_status = "complete" if not dependency_notes else "unavailable"
        else:
            dependency_notes = ["No supported lock file with pinned versions was found; dependency advisories were not checked."]
        findings.extend(dependency_findings)
        notes.extend(dependency_notes)

    findings.sort(key=lambda finding: (
        SEVERITY_ORDER.get(finding["severity"], 9), finding["category"], finding["file"], finding["line"] or 0
    ))
    summary = {severity: sum(f["severity"] == severity for f in findings) for severity in SEVERITY_ORDER}
    return {
        "repository": root.name,
        "repository_path": str(root),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": round((monotonic() - started) * 1000),
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "bytes_scanned": bytes_scanned,
        "dependencies_checked": dependency_count if dependency_check_status == "complete" else 0,
        "dependencies_found": dependency_count,
        "dependency_check_status": dependency_check_status,
        "findings_total": len(findings),
        "secrets_found": sum(f["category"] == "secrets" for f in findings),
        "vulnerable_dependencies": sum(f["category"] == "dependencies" for f in findings),
        "summary": summary,
        "notes": notes,
        "findings": findings,
    }


def to_sarif(result: dict[str, Any]) -> dict[str, Any]:
    """Convert a SecretShield result to SARIF 2.1.0 for code-scanning uploads."""
    rules_by_id: dict[str, dict[str, str]] = {}
    sarif_results = []
    levels = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    for finding in result["findings"]:
        rule_id = finding["rule_id"]
        rules_by_id.setdefault(rule_id, {"id": rule_id, "name": finding["title"], "shortDescription": {"text": finding["title"]}})
        location: dict[str, Any] = {"artifactLocation": {"uri": finding["file"], "uriBaseId": "%SRCROOT%"}}
        if finding.get("line"):
            location["region"] = {"startLine": finding["line"]}
        sarif_results.append({
            "ruleId": rule_id,
            "level": levels.get(finding["severity"], "warning"),
            "message": {"text": f"{finding['title']}: {finding['description']} Fix: {finding['recommendation']}"},
            "locations": [{"physicalLocation": location}],
            "properties": {"severity": finding["severity"], "category": finding["category"]},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "SecretShield", "version": "1.0.0", "rules": list(rules_by_id.values())}},
            "originalUriBaseIds": {"%SRCROOT%": {"uri": "./"}},
            "results": sarif_results,
        }],
    }
