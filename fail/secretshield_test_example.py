"""TEST FILE ONLY: intentionally includes insecure patterns for SecretShield demos.
Do not use these patterns in a real application. All credentials below are fake.
"""

import os
import subprocess
import requests

# ---------------- SAFE EXAMPLES (should generally not be flagged) ----------------
# Read credentials from environment variables instead of hardcoding them.
API_KEY = os.getenv("DEMO_API_KEY")

# Keep TLS certificate verification enabled (the default).
response = requests.get("https://example.com", timeout=5)

# Pass arguments as a list and avoid shell=True.
subprocess.run(["echo", "SecretShield demo"], check=False)

# ---------------- INTENTIONALLY INSECURE EXAMPLES (should be flagged) -------------

# 1. Fake hardcoded credential: expected to trigger a secret finding.
api_key = "DEMO_FAKE_SECRET_9f8a7b6c5d4e3f2a1b0c"

# 2. TLS verification disabled: expected HIGH finding.
requests.get("https://example.com", verify=False, timeout=5)

# 3. Shell execution enabled: expected HIGH finding.
subprocess.run("echo demo", shell=True, check=False)

# 4. Wildcard CORS: expected MEDIUM finding.
allow_origins = ["*"]

# 5. Debug enabled: expected MEDIUM finding.
DEBUG = True

# 6. Dynamic evaluation: expected LOW finding.
result = eval("2 + 2")

print("SecretShield demo file loaded; do not run this as production code.")
