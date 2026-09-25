# Git Secret Leak Scanner

A lightweight, zero-dependency, history-aware Git secret scanner and DevSecOps security gating tool. It traverses full commit graphs, identifies hardcoded credentials and high-entropy tokens, scores confidence and severity, supports baseline workflows, and exports audit dashboards and SARIF 2.1.0 reports for CI/CD integration.

---

## Why This Tool Exists

Committing credentials to version control is one of the leading causes of cloud account takeovers and infrastructure compromises. A common developer mistake is deleting a leaked key in a subsequent commit and assuming the issue is resolved.

In Git, **history is immutable by default**. Deleting a line in a subsequent commit merely creates a new commit containing the deletion; the secret remains permanently exposed in the commit graph, reachable via `git log -p`, `git show`, or clone mirrors.

Standard grep scripts and shallow pre-commit linters only inspect checked-out working trees (`HEAD`), providing a dangerous false sense of security. **Git Secret Leak Scanner** treats the entire Git commit history across all branches and merge commits as the true attack surface.

```
Developer commits key (Commit A) ───► Key deleted in "fix" (Commit B) ───► Current HEAD
       ▲                                                                       │
       └────────────────── Key still recoverable in history! ──────────────────┘
```

---

## Key Features

- **Full Git History Traversal**: Streams diffs across all commits, branches (`--all`), and merge resolutions (`-m`) using memory-efficient subprocess streaming.
- **Multi-Detector Engine**: 20+ precise regex signatures for major cloud providers and services (AWS, GCP, GitHub, Slack, Stripe, Twilio, SendGrid, JWT, Database URLs, PEM Private Key blocks, etc.).
- **Shannon Entropy Scoring**: Catches unrecognized, homegrown, or custom secrets with high information density that escape static signatures.
- **Dual Severity & Confidence Model**: Distinguishes structural impact (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) from detection certainty (`HIGH`, `MEDIUM`, `LOW`).
- **Context-Aware False Positive Reduction**: Boosts confidence for credential variable assignments and auth configs; downgrades confidence for documentation, example tokens, and tests.
- **Stable Baseline System**: Generates line-agnostic fingerprint baselines (`--baseline` / `--generate-baseline`) to suppress known findings and prevent CI breakage on legacy technical debt.
- **Multi-Format Reporting**: Generates colorized console output, machine-readable JSON, SARIF 2.1.0 for GitHub Code Scanning, and interactive standalone HTML audit dashboards.
- **CI/CD Security Gate**: Configurable `--fail-on` exit codes to block pull requests on unbaselined secrets meeting severity thresholds.
- **Multi-Line Key Block Capture**: Safely ingests full multi-line PEM private key bodies to generate distinct cryptographic fingerprints while preventing memory overflow.
- **HEAD Exposure vs Historical Distinction**: Immediately flags whether a leaked secret is still live in current `HEAD` or purged to historical commits.
- **Branch Attribution**: Maps each finding to reachable branch refs (`git branch --contains`), separating main-branch vulnerabilities from isolated feature branches.
- **Strict Redaction Guarantee**: Plaintext credentials are masked immediately upon discovery; raw secret strings never appear in console outputs, JSON, HTML, SARIF, or baseline files.
- **Zero Runtime Dependencies**: Built entirely with Python standard library (`argparse`, `re`, `subprocess`, `hashlib`, `json`, `math`).

---

## Architecture

The scanner operates as a modular, stream-oriented security pipeline:

```mermaid
flowchart TD
    A[Git Repository] --> B[History Traversal: git log -p --all -m]
    B --> C[Diff Stream Parsing & Hunk Tracking]
    C --> D[Path Ignore Filter .secretscannerignore]
    D --> E[Multi-Signature Regex Engine]
    D --> F[Entropy Scorer & Context Analyzer]
    E --> G[Multi-Line Key Block Assembler]
    F --> H[Confidence & Severity Assessment]
    G --> H
    H --> I[Line-Agnostic SHA-256 Fingerprinting]
    I --> J[Deduplication & Branch Attribution]
    J --> K[HEAD Exposure Check git grep]
    K --> L{Baseline Filter --baseline}
    L -->|Known Baseline Finding| M[Suppress from Active Gate]
    L -->|New Finding| N[Active Findings]
    N --> O[Redaction Engine]
    O --> P[Reports: Console / JSON / HTML / SARIF]
    N --> Q[CI Exit Code Gate --fail-on]
```

### Pipeline Stages

1. **History Traversal**: Streams unified diffs directly from `git log` via `subprocess.Popen` without buffering entire repository histories into RAM.
2. **Path Filtering**: Evaluates paths against built-in exclusions (e.g. lockfiles, binary files) and repository `.secretscannerignore` regex rules.
3. **Detection Engine**: Executes pattern matching and Shannon entropy scoring on newly added lines (`+`).
4. **Context Analysis**: Inspects surrounding tokens, variable assignments, and file names to adjust confidence ratings.
5. **Deduplication & Fingerprinting**: Computes a stable hash `SHA-256(rule:file_path:secret_value)[:16]`. Identical secrets introduced across multiple commits are collapsed into a single finding with aggregated commit metadata.
6. **HEAD Exposure & Branch Mapping**: Queries `git grep` to verify if the secret still resides in `HEAD` and identifies branch ancestry.
7. **Baseline Filtration**: Suppresses pre-existing baseline fingerprints so teams only audit newly introduced findings.
8. **Redaction & Report Dispatch**: Enforces cryptographic masking and outputs structured reports.

---

## Installation

### Prerequisites
- Python 3.9+
- Git 2.20+ installed and available on `PATH`

### Option 1: Editable / Developer Install
```bash
git clone https://github.com/aditisingh200614-oss/git-secret-scanner.git
cd git-secret-scanner
pip install -e .
```

### Option 2: Direct Execution (No Install)
```bash
python -m secretscanner --help
```

---

## Basic Usage

```bash
# Scan a local repository with full history
secretscanner /path/to/repository

# Scan current directory with JSON and HTML reports
secretscanner . --json scan_results.json --html audit_report.html

# Generate SARIF for GitHub Code Scanning
secretscanner . --sarif codeql_results.sarif

# Gate CI pipeline: fail if CRITICAL or HIGH active findings are found
secretscanner . --fail-on HIGH

# Restrict scan to current branch and latest 100 commits
secretscanner . --current-branch-only --max-commits 100

# Skip merge commits for accelerated scanning
secretscanner . --no-merges

# Filter out low-confidence entropy detections
secretscanner . --min-confidence MEDIUM
```

---

## Scanning Git History

When a commit is scanned, the engine parses unified diff hunk headers (`@@ -a,b +c,d @@`) to track exact source line numbers at the moment of introduction.

Because merge conflict resolutions can introduce credentials that do not appear in parent diffs, the scanner includes `-m` (split merge diffs) by default.

Each finding is verified against the working tree:
- `[STILL IN HEAD]`: The credential exists in the currently checked-out commit. Immediate revocation and rotation are required.
- `[purged from HEAD, in history only]`: The credential was removed in a subsequent commit but remains accessible in Git history. History rewriting (`git-filter-repo` / BFG) and credential rotation are recommended.

---

## Baselines

In legacy codebases, running a secret scanner for the first time may flag known or archived findings that cannot be remediated immediately. The baseline mechanism allows teams to establish an accepted baseline of existing findings, ensuring CI only fails on **new** leaks.

### 1. Generating a Baseline
```bash
secretscanner /path/to/repo --generate-baseline .secretscanner-baseline.json
```
This generates a structured JSON baseline containing fingerprints, rules, and file paths.

### 2. Scanning Against a Baseline
```bash
secretscanner /path/to/repo --baseline .secretscanner-baseline.json --fail-on HIGH
```
- Findings present in `.secretscanner-baseline.json` are marked as `[suppressed by baseline]` and excluded from CI failure thresholds.
- Any **new** finding introduced in subsequent commits will trigger the security gate.

### 3. Fingerprint Stability & Line Resilience
Baselines do not rely on line numbers, because adding or deleting unrelated code shifts line numbers across files. Fingerprints are calculated cryptographically:
```
Fingerprint = SHA256(rule_name + ":" + normalized_file_path + ":" + raw_secret)[:16]
```
Even if a file is refactored and a credential shifts from line 10 to line 350, the baseline continues to match accurately without false alarms.

### Security Warning on Baselines
> [!WARNING]
> Baselines are intended for operational triaging and managing legacy debt. **Baselines must NOT be used to ignore active, unrotated credentials.** Any secret recorded in a baseline is still exposed in Git history and must be revoked at the identity provider.

---

## Confidence and Severity

Git Secret Leak Scanner cleanly separates **Severity** (impact if valid) from **Confidence** (likelihood of being a true secret).

| Dimension | Definition | Scale | Examples |
|---|---|---|---|
| **Severity** | Impact of credential compromise | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` | AWS root key (`CRITICAL`), Private Key (`CRITICAL`), Slack Webhook (`HIGH`), Generic Token (`LOW`) |
| **Confidence** | Certainty that match is a true credential | `HIGH`, `MEDIUM`, `LOW` | Vendor regex prefix (`HIGH`), Generic token assigned to `API_SECRET` (`HIGH`), Raw high-entropy string (`LOW`), Example token in tutorial (`LOW`) |

### Context Heuristics

The scanner analyzes token context to refine confidence:
- **High Confidence**: Vendor-specific prefixes (`AKIA...`, `ghp_...`, `sk_live_...`), PEM blocks, or entropy strings assigned to variables like `api_key`, `secret_token`, `auth_pass`, or located in config/env files (`.env*`, `settings.py`, `auth.json`).
- **Downgraded Confidence**: Strings near words like `example`, `dummy`, `mock`, `placeholder`, or embedded inside test fixtures and markdown documentation.

---

## SARIF & GitHub Code Scanning

Static Analysis Results Interchange Format (SARIF 2.1.0) is the standard format supported by GitHub Code Scanning, GitLab Security, and DefectDojo.

### Generating SARIF
```bash
secretscanner . --sarif results.sarif
```

### GitHub Actions Integration

```yaml
name: Security Secret Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  secret-scan:
    name: Git Secret Scanner
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository with full history
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # CRITICAL: fetch full commit history

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Run Secret Scanner & Generate SARIF
        run: |
          python -m secretscanner . \
            --sarif results.sarif \
            --html report.html \
            --fail-on HIGH

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
          category: git-secret-scanner

      - name: Archive HTML Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: secret-scan-report
          path: report.html
```

---

## False Positive Management

### Sources of Noise in Secret Scanning
1. **Pinned Commit Hashes**: Lines like `uses: actions/checkout@b4ffde46...` or Git submodules look like random hex tokens. The scanner natively recognizes Git commit SHA contexts and ignores them.
2. **Documentation & Tutorial Placeholders**: Generic documentation examples in markdown.
3. **URL Anchors**: Long URI path fragments.

### Ignoring Known Safe Files
Create a `.secretscannerignore` file in the root of your repository with regex paths to ignore:
```ini
# .secretscannerignore
^tests/fixtures/
^docs/legacy/
^vendor/
```

---

## Security Considerations

1. **Synthetic Test Data Only**: Never commit real credentials for testing purposes. All tests and demo scripts in this repository utilize synthetic dummy secrets (`AKIAIOSFODNN7EXAMPLE`, `ghp_...`, `sk_live_...`).
2. **Strict Redaction**: Reports, logs, SARIF files, and baselines mask all credential spans (e.g. `AKIA••••••••MPLE`). Plaintext secrets are never stored on disk by this scanner.
3. **Remediation Protocol**: If a live secret is discovered:
   - **Step 1: Revoke/Rotate immediately** at the provider. Do not wait for Git history cleanup.
   - **Step 2: Inspect audit logs** for anomalous access during the exposure window.
   - **Step 3: Clean history** using `git-filter-repo` or BFG Repo-Cleaner if policy requires history sanitization.

---

## Testing

The project maintains an automated test suite with 100% pass rate covering detectors, entropy, multi-line blocks, baseline lifecycle, SARIF formatting, redaction guarantees, and CLI execution.

```bash
# Run full unit & integration test suite
python -m unittest discover -s tests -v

# Run Ruff linter
ruff check .
```

### Test Suite Execution Output
```
test_baseline_matches_across_line_shifts_and_detects_new_finding ... ok
test_baseline_creation_and_structure ... ok
test_baseline_save_and_load ... ok
test_duplicate_findings_deduped_in_baseline ... ok
test_filter_baseline_identifies_new_and_existing ... ok
test_invalid_baseline_handling ... ok
test_cli_basic_scan ... ok
test_cli_fail_on_threshold ... ok
test_cli_generate_and_use_baseline ... ok
test_entropy_in_auth_config_file_boosts_to_high_confidence ... ok
test_entropy_in_example_or_doc_context_lowers_confidence ... ok
test_entropy_with_positive_context_boosts_confidence ... ok
test_all_reports_redaction_consistency ... ok
test_sarif_schema_and_structure ... ok
test_sarif_strict_redaction_guarantee ... ok
...
Ran 51 tests in 6.634s
OK
```

---

## Limitations

- **No Active Key Verification**: The scanner identifies credentials based on static signatures and entropy heuristics; it does not make outbound network requests to verify if keys are active (out of scope to prevent accidental lockouts or security alerts).
- **Local Git Repository Required**: Targets local filesystem paths (`.git` directory required). Remote repositories should be cloned with `--mirror` or `--bare` prior to scanning.
- **Obfuscated / Custom Encoded Secrets**: Base64 or XOR-encrypted payloads split across multiple non-contiguous variables may escape entropy detection.
- **Binary Files**: Non-text diffs are excluded from regex parsing to maintain performance.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
