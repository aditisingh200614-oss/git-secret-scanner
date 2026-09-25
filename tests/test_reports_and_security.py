"""
test_reports_and_security.py
Tests verifying report formatting (JSON, HTML) and zero-plaintext-secret leakage.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secretscanner.baseline import write_baseline
from secretscanner.report import (
    write_html_report,
    write_json_report,
)
from secretscanner.sarif import write_sarif_report
from secretscanner.scanner import Finding


class TestReportsAndSecurity(unittest.TestCase):
    def setUp(self):
        self.raw_key = "AKIAIOSFODNN7EXAMPLE"
        self.raw_pass = "Sup3rSecretPass!2024"

        self.findings = [
            Finding(
                rule="AWS Access Key ID",
                severity="CRITICAL",
                confidence="HIGH",
                file_path="config/aws.py",
                commit_hash="1111111111111111111111111111111111111111",
                commit_short="1111111",
                author="Security Tester",
                date="2026-09-25T00:00:00Z",
                line_number=4,
                line_preview='AWS_KEY = "AKIA••••••••MPLE"',
                secret_fingerprint="fp_test_aws_key",
                still_in_head=True,
                branches=["main"],
                context_reason="Rigid AWS AKIA key signature",
            ),
            Finding(
                rule="Database Connection String w/ Credentials",
                severity="CRITICAL",
                confidence="HIGH",
                file_path="db/conn.py",
                commit_hash="2222222222222222222222222222222222222222",
                commit_short="2222222",
                author="Dev Tester",
                date="2026-09-25T01:00:00Z",
                line_number=8,
                line_preview='DATABASE_URL = "postgres://admin:••••••••@prod-db:5432/main"',
                secret_fingerprint="fp_test_db_pass",
                still_in_head=False,
                branches=["main", "feature/db"],
                context_reason="Database connection string with inline password",
            ),
        ]

    def test_json_report_structure_and_redaction(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = os.path.join(tmpdir, "report.json")
            write_json_report(self.findings, "/repo/path", json_path, baseline_suppressed=1)

            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)

            self.assertEqual(data["total_active_findings"], 2)
            self.assertEqual(data["baseline_suppressed_count"], 1)
            self.assertEqual(data["summary_by_severity"]["CRITICAL"], 2)
            self.assertEqual(data["summary_by_confidence"]["HIGH"], 2)
            self.assertEqual(data["still_in_head_count"], 1)

            with open(json_path, encoding="utf-8") as f:
                raw_text = f.read()
            self.assertNotIn(self.raw_key, raw_text)
            self.assertNotIn(self.raw_pass, raw_text)

    def test_html_report_dashboard_and_redaction(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            html_path = os.path.join(tmpdir, "report.html")
            write_html_report(self.findings, "/repo/path", html_path, baseline_suppressed=2)

            with open(html_path, encoding="utf-8") as f:
                html_text = f.read()

            self.assertIn("Git Secret Leak Security Report", html_text)
            self.assertIn("CRITICAL", html_text)
            self.assertIn("HIGH CONFIDENCE", html_text)
            self.assertIn("LIVE IN HEAD", html_text)
            self.assertIn("searchInput", html_text)
            self.assertIn("Baseline active: 2", html_text)

            # Security verification: plaintext secrets MUST NOT exist in HTML
            self.assertNotIn(self.raw_key, html_text)
            self.assertNotIn(self.raw_pass, html_text)

    def test_all_reports_redaction_consistency(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = os.path.join(tmpdir, "out.json")
            html_path = os.path.join(tmpdir, "out.html")
            sarif_path = os.path.join(tmpdir, "out.sarif")
            base_path = os.path.join(tmpdir, "base.json")

            write_json_report(self.findings, "/repo", json_path)
            write_html_report(self.findings, "/repo", html_path)
            write_sarif_report(self.findings, "/repo", sarif_path)
            write_baseline(self.findings, "/repo", base_path)

            for path in [json_path, html_path, sarif_path, base_path]:
                with open(path, encoding="utf-8") as f:
                    content = f.read()
                self.assertNotIn(self.raw_key, content, f"Leaked raw secret in {path}")
                self.assertNotIn(self.raw_pass, content, f"Leaked raw secret in {path}")


if __name__ == "__main__":
    unittest.main()
