"""
SecretShield clean test example.

This file intentionally avoids common insecure patterns so you can compare
a clean scan with secretshield_test_example.py.

Expected result:
- No hardcoded credentials
- TLS certificate verification remains enabled
- No shell=True subprocess calls
- No wildcard CORS configuration
- Debug mode is disabled
- No eval() or exec() calls
"""

import os
import subprocess
from urllib.request import urlopen


def get_api_key() -> str | None:
    """Read a secret from the environment instead of hardcoding it."""
    return os.environ.get("SERVICE_API_KEY")


def fetch_status(url: str) -> bytes:
    """Fetch a URL using the standard library's default TLS verification."""
    with urlopen(url, timeout=10) as response:
        return response.read()


def list_directory(path: str) -> list[str]:
    """List directory entries without invoking a shell."""
    result = subprocess.run(
        ["python", "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    # Keep the example harmless and use the supplied path as data.
    return sorted(os.listdir(path))


def cors_config() -> dict[str, object]:
    """Use an explicit trusted origin instead of a wildcard."""
    return {
        "allow_origins": ["https://example.com"],
        "allow_methods": ["GET", "POST"],
    }


DEBUG = False


def main() -> None:
    """Print safe configuration checks without exposing secret values."""
    print("Debug mode:", DEBUG)
    print("API key configured:", bool(get_api_key()))
    print("CORS origins:", ", ".join(cors_config()["allow_origins"]))
    print("TLS verification: enabled by default")
    print("Shell execution: not used")
    print("Dynamic eval/exec: not used")


if __name__ == "__main__":
    main()
