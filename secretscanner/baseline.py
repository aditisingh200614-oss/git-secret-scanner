"""
baseline.py
Baseline management for accepted/known findings in Git Secret Leak Scanner.

Allows teams to record existing historical findings into a baseline file
so that subsequent scans only alert and fail CI on NEW secrets.
Fingerprints are content- and rule-based (not line-number based) so that
line edits and code refactoring do not invalidate baseline matches.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any


def generate_baseline_dict(findings: list[Any], repo_path: str = "") -> dict[str, Any]:
    """
    Constructs the dictionary representing a baseline of findings.
    Only redacted previews and SHA-256 fingerprints are stored.
    """
    unique_fingerprints = sorted({f.secret_fingerprint for f in findings})
    entries = []
    seen = set()

    for f in findings:
        if f.secret_fingerprint in seen:
            continue
        seen.add(f.secret_fingerprint)
        entries.append({
            "fingerprint": f.secret_fingerprint,
            "rule": f.rule,
            "severity": f.severity,
            "confidence": getattr(f, "confidence", "HIGH"),
            "file_path": f.file_path,
            "line_preview": f.redacted(),
            "commit_short": f.commit_short,
            "author": f.author,
            "date": f.date,
            "still_in_head": f.still_in_head,
        })

    return {
        "version": "1.0",
        "generator": "git-secret-scanner",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "repository": repo_path,
        "total_findings": len(entries),
        "fingerprints": unique_fingerprints,
        "findings": entries,
    }


def write_baseline(findings: list[Any], repo_path: str, output_path: str) -> str:
    """Writes findings to a baseline JSON file."""
    data = generate_baseline_dict(findings, repo_path)
    # Ensure directory exists if path includes directories
    parent_dir = os.path.dirname(output_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return output_path


def load_baseline(baseline_path: str) -> set[str]:
    """
    Loads a baseline file and returns the set of known finding fingerprints.
    Raises ValueError or FileNotFoundError if baseline is invalid or unreadable.
    """
    if not os.path.exists(baseline_path):
        raise FileNotFoundError(f"Baseline file not found: {baseline_path}")

    try:
        with open(baseline_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid baseline JSON format in {baseline_path}: {e}")
    except OSError as e:
        raise ValueError(f"Unable to read baseline file {baseline_path}: {e}")

    if not isinstance(data, dict):
        raise ValueError(f"Invalid baseline format: expected JSON object in {baseline_path}")

    # Extract fingerprints from either 'fingerprints' list or 'findings' list
    fingerprints: set[str] = set()

    if "fingerprints" in data and isinstance(data["fingerprints"], list):
        for fp in data["fingerprints"]:
            if isinstance(fp, str) and fp.strip():
                fingerprints.add(fp.strip())

    if "findings" in data and isinstance(data["findings"], list):
        for item in data["findings"]:
            if isinstance(item, dict) and "fingerprint" in item:
                fp = item["fingerprint"]
                if isinstance(fp, str) and fp.strip():
                    fingerprints.add(fp.strip())

    if not fingerprints and "fingerprints" not in data and "findings" not in data:
        raise ValueError(f"Invalid baseline file: missing 'fingerprints' or 'findings' in {baseline_path}")

    return fingerprints


def filter_baseline_findings(
    findings: list[Any],
    baseline_fingerprints: set[str]
) -> tuple[list[Any], list[Any]]:
    """
    Splits findings into (new_findings, baseline_findings) based on known fingerprints.
    """
    new_findings = []
    baseline_findings = []

    for f in findings:
        if f.secret_fingerprint in baseline_fingerprints:
            baseline_findings.append(f)
        else:
            new_findings.append(f)

    return new_findings, baseline_findings
