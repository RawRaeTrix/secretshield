# SecretShield

**A calmer way to catch the security issues hiding in a repository.**

SecretShield scans for exposed credentials, known vulnerabilities in pinned dependencies, and a focused set of risky code patterns. Review findings in a friendly local dashboard or wire the scanner into a GitHub Actions workflow.

SecretShield is built with Python's standard library. There are no runtime packages to install, no account to create, and no source code uploaded to a service.

## A quick look

- **The dashboard** gives each finding a location, a plain-language explanation and a useful next step.
- **The CLI** returns a readable summary or machine-ready JSON and SARIF.
- **The CI action** can publish findings to GitHub code scanning and apply a severity threshold.
- **Credential matches are redacted.** The scanner never puts the matched value in its findings or report.

## Get started

You’ll need Python 3.11 or newer. Open a terminal in this project directory.

```bash
python app.py
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765), choose **Git repository** or **Any folder**, paste a local folder path, and scan it. Repository mode accepts folders inside a Git worktree; Any folder mode does not require Git. Relative paths resolve from the SecretShield folder. For example, on Windows:

```text
C:\Users\you\Projects\my-app
```

The dashboard starts in **sample mode** so you can explore the interface without scanning anything. The sample rows are made-up examples; run a scan to replace them with your own results.

Stop the dashboard with `Ctrl+C`.

## Use the command line

Install the project once to add the `secretshield` command:

```bash
python -m pip install .
secretshield /path/to/repository
```

PowerShell example:

```powershell
python -m pip install .
secretshield "C:\Users\you\Projects\my-app"
```

The default policy returns exit code `1` when it finds a **high** or **critical** issue, which makes it useful in automation. Choose a different threshold when you need to:

```bash
secretshield . --fail-on critical
secretshield . --fail-on medium --format json --output secretshield-report.json
secretshield . --format sarif --output secretshield.sarif --fail-on none
```

Available formats are `table`, `json` and `sarif`. Use `--no-dependencies` when you want an offline scan of files and code only. `secretshield --help` lists all options.

## Checks included

### Exposed credentials

SecretShield recognizes common AWS access keys, GitHub and Slack tokens, Stripe live keys, Google API keys, JWTs, private-key headers, and likely high-entropy values assigned to credential-like fields such as `password`, `api_key` and `client_secret`.

Each secret finding shows its file and line. Its evidence replaces the matched value with `[REDACTED]`.

### Vulnerable dependencies

When dependency checks are on, SecretShield reads exact versions from:

- `package-lock.json`
- Pinned `requirements*.txt` entries using `==` or `===`
- `poetry.lock`
- `Cargo.lock`
- `go.sum`

It checks these resolved versions against [OSV](https://osv.dev) and includes an advisory link and a fixed version when OSV provides one. Dependency checks need an internet connection. If the service is unavailable, the scan finishes and explains that the check did not complete; it does not claim the dependencies are clear. SecretShield checks lock files rather than guessing from version ranges in a manifest.

### Common code risks

The focused rules flag disabled TLS verification, `shell=True` in common Python subprocess calls, wildcard CORS origins, enabled `DEBUG`, and dynamic `eval` or `exec` calls. These rules look for recognizable patterns and do not replace a full static-analysis review.

## Add it to GitHub Actions

The project includes a composite action at `.github/actions/secretshield` and an example workflow at `.github/workflows/secretshield.yml`. The workflow checks out a repository, runs the scan and uploads the SARIF report to GitHub code scanning.

To use the composite action from another repository, publish this project and a release tag first, then add a step like this to that repository's workflow:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v7
  - uses: your-org/secretshield/.github/actions/secretshield@v1
    with:
      path: .
      fail-on: high
```

Replace `your-org/secretshield` with the repository where you published this project. The action uploads SARIF even when the chosen severity threshold fails the job. GitHub code scanning must be available for the target repository.

You can also install SecretShield in your own workflow and call the CLI directly:

```yaml
- run: python -m pip install .
- run: secretshield . --format sarif --output secretshield.sarif --fail-on high
- if: always()
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: secretshield.sarif
```

## Privacy and scope

Scans run against files on your computer or CI runner. SecretShield does **not** upload source files. If dependency checks are enabled, it sends resolved package names, ecosystems and versions to the public OSV API to look up advisories. Turn off the **Check dependencies** option or pass `--no-dependencies` to avoid that network request.

The local dashboard binds to `127.0.0.1` by default. Keep it there: anyone who can reach the dashboard could ask it to scan directories available to the computer running it. Do not expose the dashboard on a network interface you do not trust.

SecretShield is a practical first pass. It can miss credentials and security issues, and a matching code pattern may need human review. It is not a substitute for peer review, runtime controls, or a broader SAST and software-composition-analysis program.

## Make the scan your own

Add repository-relative glob patterns to `.secretshieldignore`, one per line:

```gitignore
generated/**
fixtures/local-only/**
```

SecretShield also skips common build output and dependency directories, symlinks, binary files and files larger than 3 MB. It stops after 20,000 readable files or about 512 MB of content and tells you when a safety limit or an unavailable dependency check affects a scan.

## Project layout

```text
app.py                         Local dashboard server
secretshield/scanner.py        Scanner rules, OSV lookup and SARIF export
secretshield/cli.py            Command-line interface
web/                           Dashboard assets
.github/actions/secretshield/  Reusable GitHub composite action
.github/workflows/             Example CI workflow
```

## License

MIT. See [LICENSE](LICENSE).
