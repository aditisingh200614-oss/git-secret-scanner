"""
sarif.py
Generates standard SARIF 2.1.0 (Static Analysis Results Interchange Format)
reports for GitHub Code Scanning and other DevSecOps compliance tooling.

Guarantees:
- Strict SARIF 2.1.0 JSON schema compliance
- Zero plaintext secret leakage: all snippets and messages are fully redacted
- Rich metadata: commit info, branch reachability, severity, confidence, fingerprints
"""

import json
import os
import re
from typing import Any


def sanitize_rule_id(rule_name: str) -> str:
    """Creates a deterministic, clean SARIF rule ID."""
    clean = re.sub(r"[^A-Za-z0-9]+", "_", rule_name.strip()).strip("_").upper()
    return f"SEC_{clean}"


def severity_to_sarif_level(severity: str) -> str:
    """Maps scanner severity to SARIF result levels."""
    sev = severity.upper()
    if sev in ("CRITICAL", "HIGH"):
        return "error"
    if sev == "MEDIUM":
        return "warning"
    return "note"


def generate_sarif_dict(findings: list[Any], repo_path: str = "") -> dict[str, Any]:
    """
    Constructs a valid SARIF 2.1.0 document dictionary from a list of findings.
    """
    # Collect unique rules from findings
    rule_map: dict[str, dict[str, Any]] = {}

    for f in findings:
        rule_id = sanitize_rule_id(f.rule)
        if rule_id not in rule_map:
            rule_map[rule_id] = {
                "id": rule_id,
                "name": f.rule.replace(" ", ""),
                "shortDescription": {
                    "text": f"{f.rule} detected in repository history"
                },
                "fullDescription": {
                    "text": f"Potential {f.rule} discovered in Git commit history. "
                            f"Severity: {f.severity}, Confidence: {getattr(f, 'confidence', 'HIGH')}."
                },
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(f.severity)
                },
                "properties": {
                    "tags": ["security", "secret", "credential", "devsecops"],
                    "precision": "high" if getattr(f, "confidence", "HIGH") == "HIGH" else "medium",
                    "severity": f.severity,
                    "confidence": getattr(f, "confidence", "HIGH"),
                },
            }

    rules_list = list(rule_map.values())
    rule_id_to_index = {r["id"]: idx for idx, r in enumerate(rules_list)}

    results = []
    for f in findings:
        rule_id = sanitize_rule_id(f.rule)
        rule_index = rule_id_to_index.get(rule_id, 0)
        conf = getattr(f, "confidence", "HIGH")
        head_status = "STILL PRESENT in HEAD" if f.still_in_head else "Purged from HEAD, found in history"

        branch_info = f" (branches: {', '.join(f.branches)})" if f.branches else ""
        message_text = (
            f"[{f.severity}/{conf}] {f.rule} detected in '{f.file_path}:{f.line_number}' "
            f"by commit {f.commit_short} ({f.author}, {f.date}){branch_info}. Status: {head_status}."
        )

        loc = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": f.file_path.replace("\\", "/"),
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {
                    "startLine": max(1, f.line_number),
                    "snippet": {
                        "text": f.redacted(),
                    },
                },
            }
        }

        results.append({
            "ruleId": rule_id,
            "ruleIndex": rule_index,
            "level": severity_to_sarif_level(f.severity),
            "message": {
                "text": message_text,
            },
            "locations": [loc],
            "properties": {
                "rule": f.rule,
                "severity": f.severity,
                "confidence": conf,
                "detectionMethod": f.detection_method,
                "fingerprint": f.secret_fingerprint,
                "commitHash": f.commit_hash,
                "commitShort": f.commit_short,
                "author": f.author,
                "date": f.date,
                "stillInHead": f.still_in_head,
                "branches": f.branches,
                "keyBlockLines": getattr(f, "key_block_lines", 0),
            },
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "git-secret-scanner",
                        "version": "2.0.0",
                        "semanticVersion": "2.0.0",
                        "informationUri": "https://github.com/aditisingh200614-oss/git-secret-scanner",
                        "rules": rules_list,
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif_report(findings: list[Any], repo_path: str, output_path: str) -> str:
    """Generates and writes SARIF 2.1.0 JSON report to output_path."""
    sarif_data = generate_sarif_dict(findings, repo_path)
    parent_dir = os.path.dirname(output_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(sarif_data, fh, indent=2)
    return output_path
