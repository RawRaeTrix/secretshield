"""Command-line interface for SecretShield."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .scanner import SEVERITY_ORDER, scan_repository, to_sarif


def _table(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        f"\n  SecretShield  ·  {result['repository']}",
        f"  {result['files_scanned']:,} files scanned  ·  {result['dependencies_checked']:,} locked dependencies checked  ·  {result['duration_ms']} ms",
        f"  {result['findings_total']} findings  |  {summary['critical']} critical  ·  {summary['high']} high  ·  {summary['medium']} medium  ·  {summary['low']} low",
    ]
    for finding in result["findings"]:
        location = finding["file"] + (f":{finding['line']}" if finding.get("line") else "")
        lines.extend([
            f"\n  [{finding['severity'].upper():8}] {finding['title']}",
            f"              {location}  ·  {finding['rule_id']}",
            f"              {finding['recommendation']}",
        ])
    if not result["findings"]:
        lines.append("\n  No findings in the checks that completed. Keep dependencies and rules up to date.")
    if result["notes"]:
        lines.append("\n  Notes:")
        lines.extend(f"    - {note}" for note in result["notes"])
    lines.append("")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secretshield", description="Scan a repository for secrets and common security risks.")
    parser.add_argument("repository", nargs="?", default=".", help="Repository folder to scan (default: current folder)")
    parser.add_argument("--format", choices=("table", "json", "sarif"), default="table", help="Output format")
    parser.add_argument("--output", help="Write JSON or SARIF output to this file")
    parser.add_argument("--no-dependencies", action="store_true", help="Skip OSV vulnerability checks for locked dependencies")
    parser.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "none"), default="high",
                        help="Exit with status 1 when findings reach this severity (default: high)")
    parser.add_argument("--version", action="version", version="SecretShield 1.0.0")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = scan_repository(args.repository, include_dependencies=not args.no_dependencies)
    except (ValueError, OSError) as error:
        print(f"SecretShield: {error}", file=sys.stderr)
        return 2

    if args.format == "json":
        output = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    elif args.format == "sarif":
        output = json.dumps(to_sarif(result), indent=2, ensure_ascii=False) + "\n"
    else:
        output = _table(result)

    if args.output:
        try:
            destination = Path(args.output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(output, encoding="utf-8")
        except OSError as error:
            print(f"SecretShield: could not write output: {error}", file=sys.stderr)
            return 2
        if args.format == "table":
            print(output, end="")
        else:
            print(f"SecretShield: {args.format.upper()} report saved to {destination}")
    else:
        print(output, end="")

    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(item["severity"], 9) <= threshold for item in result["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
