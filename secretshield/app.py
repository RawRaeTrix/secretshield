"""Run the SecretShield local dashboard with only the Python standard library."""

from __future__ import annotations

import argparse
import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from secretshield.scanner import scan_repository

ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "web"
MAX_REQUEST_BYTES = 8192


def _inside_git_repository(path: Path) -> bool:
    """Return whether a directory is inside a Git worktree or repository."""
    current = path.resolve()
    if current.is_file():
        current = current.parent
    for directory in (current, *current.parents):
        marker = directory / ".git"
        if marker.is_dir() or marker.is_file():
            return True
    return False


class SecretShieldHandler(BaseHTTPRequestHandler):
    server_version = "SecretShield/1.0"

    def _send(self, status: int, payload: bytes, content_type: str, extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, status: int, value: object) -> None:
        payload = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self._send(status, payload, "application/json; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler method name
        requested = urlsplit(self.path).path
        if requested == "/api/health":
            self._json(200, {"ok": True, "name": "SecretShield", "version": "1.0.0"})
            return

        relative = "index.html" if requested == "/" else requested.lstrip("/")
        target = (WEB_ROOT / relative).resolve()
        try:
            target.relative_to(WEB_ROOT.resolve())
        except ValueError:
            self._json(404, {"error": "Not found"})
            return
        if not target.is_file():
            self._json(404, {"error": "Not found"})
            return
        try:
            payload = target.read_bytes()
        except OSError:
            self._json(404, {"error": "Not found"})
            return
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        charset = "; charset=utf-8" if content_type.startswith(("text/", "application/javascript", "application/json")) else ""
        self._send(200, payload, content_type + charset)

    def do_POST(self) -> None:  # noqa: N802
        if urlsplit(self.path).path != "/api/scan":
            self._json(404, {"error": "Not found"})
            return

        origin = self.headers.get("Origin")
        request_host = self.headers.get("Host", "")
        if origin:
            parsed_origin = urlsplit(origin)
            if parsed_origin.scheme != "http" or parsed_origin.netloc.lower() != request_host.lower():
                self._json(403, {"error": "Open SecretShield from its local dashboard before starting a scan."})
                return
        if self.headers.get_content_type() != "application/json":
            self._json(415, {"error": "Send scan options as JSON."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length < 1 or length > MAX_REQUEST_BYTES:
            self._json(413, {"error": "Scan request is empty or too large."})
            return
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(400, {"error": "The scan request was not valid JSON."})
            return
        if not isinstance(data, dict) or not isinstance(data.get("path"), str) or not data["path"].strip():
            self._json(400, {"error": "Enter the path to a folder on this computer."})
            return
        scope = data.get("scope", "folder")
        if not isinstance(scope, str) or scope not in {"repository", "folder"}:
            self._json(400, {"error": "Choose either Git repository or Any folder scan scope."})
            return
        repository_path = data["path"].strip()
        # Windows Explorer's "Copy as path" wraps paths in quotes. Accept
        # that form, and make relative paths predictable even when the server
        # was launched from a different working directory.
        if len(repository_path) >= 2 and repository_path[0] == repository_path[-1] and repository_path[0] in "\"'":
            repository_path = repository_path[1:-1].strip()
        parsed_path = Path(repository_path).expanduser()
        if not parsed_path.is_absolute():
            app_relative_path = (ROOT / parsed_path).resolve()
            if app_relative_path.exists():
                parsed_path = app_relative_path
        if scope == "repository" and parsed_path.is_dir() and not _inside_git_repository(parsed_path):
            self._json(400, {"error": "This folder is not inside a Git repository. Choose “Any folder” to scan it anyway."})
            return
        try:
            result = scan_repository(parsed_path, include_dependencies=bool(data.get("include_dependencies", True)))
        except (ValueError, OSError) as error:
            self._json(400, {"error": str(error)})
            return
        self._json(200, result)

    def log_message(self, format: str, *args: object) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Start the SecretShield local dashboard.")
    parser.add_argument("--host", default="127.0.0.1", help="Interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Dashboard port (default: 8765)")
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), SecretShieldHandler)
    print("\n  SecretShield is ready.")
    print(f"  Open http://127.0.0.1:{args.port} in your browser.")
    print("  Scans stay on this computer; dependency advisories are checked with OSV when online.")
    print("  Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  SecretShield stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
