"""
test_sarif.py
Unit tests for SARIF 2.1.0 output formatting, rule metadata, and strict redaction verification.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secretscanner.sarif import generate_sarif_dict, write_sarif_report
from secretscanner.scanner import Finding


class TestSarifOutput(unittest.TestCase):
    def setUp(self):
        self.secret_raw_1 = "AKIAIOSFODNN7EXAMPLE"
        self.secret_raw_2 = "sk_" + "live_DUMMYTESTKEYFORSCANNERTEST0000000000000"

        self.finding1 = Finding(
            rule="AWS Access Key ID",
            severity="CRITICAL",
            confidence="HIGH",
            file_path="src/aws.py",
            commit_hash="a1b2c3d4e5f6789012345678901234567890abcd",
            commit_short="a1b2c3d",
            author="Dev One",
            date="2026-09-25T08:00:00Z",
            line_number=10,
            line_preview='AWS_KEY = "AKIA••••••••MPLE"',
            secret_fingerprint="fp_aws_001",
            still_in_head=True,
            branches=["main", "feature/auth"],
            context_reason="Rigid AWS AKIA key signature detected",
        )
        self.finding2 = Finding(
            rule="Stripe Live Secret Key",
            severity="CRITICAL",
            confidence="HIGH",
            file_path="src/billing.py",
            commit_hash="b2c3d4e5f6789012345678901234567890abcdef",
            commit_short="b2c3d4e",
            author="Dev Two",
            date="2026-09-25T08:30:00Z",
            line_number=25,
            line_preview='STRIPE_KEY = "sk_l••••••••0000"',
            secret_fingerprint="fp_stripe_002",
            still_in_head=False,
            branches=["main"],
            context_reason="Stripe live secret key signature",
        )

    def test_sarif_schema_and_structure(self):
        sarif = generate_sarif_dict([self.finding1, self.finding2], repo_path="/mock/repo")

        # Verify top-level SARIF requirements
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("$schema", sarif)
        self.assertEqual(len(sarif["runs"]), 1)

        run = sarif["runs"][0]
        driver = run["tool"]["driver"]
        self.assertEqual(driver["name"], "git-secret-scanner")
        self.assertEqual(len(driver["rules"]), 2)

        # Verify results
        results = run["results"]
        self.assertEqual(len(results), 2)

        r1 = results[0]
        self.assertEqual(r1["ruleId"], "SEC_AWS_ACCESS_KEY_ID")
        self.assertEqual(r1["level"], "error")
        self.assertEqual(r1["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "src/aws.py")
        self.assertEqual(r1["locations"][0]["physicalLocation"]["region"]["startLine"], 10)
        self.assertEqual(r1["properties"]["severity"], "CRITICAL")
        self.assertEqual(r1["properties"]["confidence"], "HIGH")
        self.assertEqual(r1["properties"]["stillInHead"], True)
        self.assertIn("main", r1["properties"]["branches"])

    def test_sarif_file_write_and_reload(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sarif_file = os.path.join(tmpdir, "results.sarif")
            write_sarif_report([self.finding1, self.finding2], "/mock/repo", sarif_file)

            self.assertTrue(os.path.exists(sarif_file))
            with open(sarif_file, encoding="utf-8") as f:
                loaded = json.load(f)
            self.assertEqual(loaded["version"], "2.1.0")
            self.assertEqual(len(loaded["runs"][0]["results"]), 2)

    def test_sarif_strict_redaction_guarantee(self):
        sarif = generate_sarif_dict([self.finding1, self.finding2], repo_path="/mock/repo")
        sarif_json_str = json.dumps(sarif, ensure_ascii=False)

        # Raw secrets must never appear anywhere in the SARIF output
        self.assertNotIn(self.secret_raw_1, sarif_json_str)
        self.assertNotIn(self.secret_raw_2, sarif_json_str)
        # Redacted indicators must appear
        self.assertIn("AKIA••••••••MPLE", sarif_json_str)


if __name__ == "__main__":
    unittest.main()
