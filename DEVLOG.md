# Development Log & Architectural Notes

Engineering journal detailing design decisions, self-reviews, false-positive investigations, and DevSecOps production upgrades for `git-secret-scanner`.

---

## 1. Initial Self-Review: Addressing Core Flaws in V1

The initial prototype proved the viability of streaming history diffs, but a security audit revealed several critical flaws:

1. **Flawed Redaction Model in Early Prototype**:
   - *Problem*: The initial draft truncated lines to 140 characters rather than masking the secret itself. This meant full 40-character AWS keys or tokens were still written in plaintext into JSON/HTML reports, turning security reports into a secondary vulnerability.
   - *Fix*: Created `redact.py`. The scanner masks only the sensitive regex span or entropy token (e.g. `AKIA••••••••MPLE`), leaving variable names and context visible while destroying the secret payload.
2. **Hunk Tracking for Real Line Numbers**:
   - *Problem*: `line_number` was initially hardcoded to `-1`.
   - *Fix*: Implemented stateful parsing of unified diff hunk headers (`@@ -a,b +c,d @@`), tracking additions (`+`) to pinpoint exact source line positions at commit time.
3. **Merge Commit Coverage**:
   - *Problem*: Standard `git log -p` omits merge commit diffs, leaving a blind spot where conflicts resolved by committing credentials go undetected.
   - *Fix*: Added `-m` flag to split merge diffs by default (`--no-merges` available for performance tuning).
4. **Subprocess Streaming vs Memory Buffering**:
   - *Problem*: Loading entire repository histories into memory crashed on large repos.
   - *Fix*: Utilized `subprocess.Popen` with line-by-line streaming via standard iterators, keeping memory consumption constant regardless of commit history size.

---

## 2. Real-World Validation Against `pallets/flask` (6,300+ Commits)

Testing against synthetic fixtures only validates the happy path. The engine was run against `pallets/flask` (~740,000 added lines across history):

- **Initial Run**: 286 findings, all from the Shannon entropy detector.
  - *Diagnosis*: 240 findings were GitHub Actions SHA hashes (e.g., `uses: actions/checkout@3d3c...`) and pre-commit hook revisions. 46 findings were Git submodule commit pointers.
  - *Fix*: Added `is_git_commit_reference()` in `entropy.py` to filter out commit SHA hashes.
- **Second Investigation**: Long URL anchors in documentation triggered high entropy.
  - *Fix*: Excluded candidate tokens overlapping `http://` or `https://` URI spans.
- **Outcome**: Reduced false positives to 7 defensible occurrences (tutorial example keys in `docs/`), achieving **0 regex false positives** across 740k lines.

---

## 3. Production DevSecOps Upgrade (V2)

To advance `git-secret-scanner` into a production DevSecOps gating engine, four major capabilities were engineered:

### A. Baseline System (`secretscanner/baseline.py`)
- **Problem**: Enforcing secret scanning on existing repositories often fails due to legacy findings that teams cannot immediately rotate.
- **Design Choice: Line-Resilient Fingerprints**:
  - Relying on `file:line` breaks whenever any line is inserted above a finding.
  - Solution: Fingerprint computed as `SHA256(rule + ":" + normalized_path + ":" + raw_secret)[:16]`.
  - Result: Code refactorings and line shifts do not invalidate baseline entries.
- **Workflow**: `--generate-baseline` writes a structured schema containing metadata, rule IDs, and fingerprints; `--baseline` filters out known entries while continuing to alert on newly committed secrets.

### B. Dual-Axis Finding Model: Severity + Confidence
- **Separation of Concerns**:
  - `Severity` reflects the blast radius if genuine (e.g., AWS Root Key is `CRITICAL`, Generic Token is `LOW`).
  - `Confidence` reflects the statistical/pattern certainty (e.g., Known Vendor Regex is `HIGH`, Raw Entropy is `LOW`).
- **Context-Aware Heuristics (`entropy.py`)**:
  - Positive context signals (variable names matching `token|key|secret|password|auth` or files like `.env`, `settings.py`, `config.json`) boost entropy findings to `HIGH` or `MEDIUM` confidence.
  - Negative context signals (`example`, `sample`, `test`, `dummy`, `mock`, markdown files) reduce confidence to `LOW` and add explanatory audit rationale.

### C. SARIF 2.1.0 Exporter (`secretscanner/sarif.py`)
- Engineered a compliant Static Analysis Results Interchange Format (SARIF 2.1.0) generator.
- Maps scanner rules to SARIF rule descriptors, tags findings with commit/branch metadata, and maps severities to CodeQL levels (`error`, `warning`, `note`).
- Enforces strict redaction guarantees so that SARIF files uploaded to GitHub Code Scanning or third-party SIEMs never leak sensitive material.

### D. Interactive Security Report Dashboard (`secretscanner/report.py`)
- Overhauled the HTML report with a dark-mode DevSecOps dashboard.
- Includes real-time summary cards (Active Findings, HEAD Exposure, Severity/Confidence splits), distribution charts, and client-side instant search/filtering (by severity, confidence, HEAD status, and keywords) without external JavaScript frameworks.

---

## 4. Test Suite Architecture

The test suite in `tests/` contains 51 automated tests covering:
1. `test_detectors.py`: Pattern matching across 20+ vendors, multi-line PEM key body accumulation, branch attribution, and merge traversal.
2. `test_baseline.py`: Baseline schema creation, deserialization, duplicate suppression, invalid JSON handling, and line-shift verification.
3. `test_confidence_and_context.py`: Vendor signature confidence, positive/negative variable context signals, and placeholder rejections.
4. `test_sarif.py`: SARIF 2.1.0 schema compliance, URI normalization, and strict redaction verification.
5. `test_reports_and_security.py`: JSON, HTML, and SARIF export consistency ensuring zero plaintext secret leaks.
6. `test_cli.py`: End-to-end CLI execution, exit code assertions (`--fail-on`), and baseline integration.

---

## 5. Summary of Key Metrics

- **Zero Third-Party Dependencies**: Pure Python standard library implementation.
- **Cross-Platform Compatibility**: Tested and verified on Windows, Linux, and macOS.
- **Linter Compliance**: 0 errors on `ruff check .`.
- **Test Coverage**: 51/51 passing tests in under 7 seconds.
