"""
test_baseline.py
Unit tests for baseline generation, loading, schema validation, line-shift resilience,
and new-finding differential reporting.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secretscanner.baseline import (
    filter_baseline_findings,
    generate_baseline_dict,
    load_baseline,
    write_baseline,
)
from secretscanner.scanner import Finding, scan_repository


class TestBaselineUnit(unittest.TestCase):
    def setUp(self):
        self.finding1 = Finding(
            rule="AWS Access Key ID",
            severity="CRITICAL",
            confidence="HIGH",
            file_path="config.py",
            commit_hash="c111111111111111111111111111111111111111",
            commit_short="c111111",
            author="Dev One",
            date="2026-09-20T10:00:00Z",
            line_number=5,
            line_preview='AWS_KEY = "AKIA••••••••MPLE"',
            secret_fingerprint="fp_aws_key_00001",
            still_in_head=True,
        )
        self.finding2 = Finding(
            rule="GitHub Personal Access Token",
            severity="HIGH",
            confidence="HIGH",
            file_path="ci.py",
            commit_hash="c222222222222222222222222222222222222222",
            commit_short="c222222",
            author="Dev Two",
            date="2026-09-21T10:00:00Z",
            line_number=12,
            line_preview='GH_TOKEN = "ghp_••••••••1234"',
            secret_fingerprint="fp_gh_token_0002",
            still_in_head=False,
        )

    def test_baseline_creation_and_structure(self):
        b_dict = generate_baseline_dict([self.finding1, self.finding2], repo_path="/mock/repo")
        self.assertEqual(b_dict["version"], "1.0")
        self.assertEqual(b_dict["total_findings"], 2)
        self.assertIn("fp_aws_key_00001", b_dict["fingerprints"])
        self.assertIn("fp_gh_token_0002", b_dict["fingerprints"])
        self.assertEqual(len(b_dict["findings"]), 2)

    def test_baseline_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline_path = os.path.join(tmpdir, "baseline.json")
            write_baseline([self.finding1, self.finding2], "/mock/repo", baseline_path)

            loaded_fps = load_baseline(baseline_path)
            self.assertEqual(loaded_fps, {"fp_aws_key_00001", "fp_gh_token_0002"})

    def test_filter_baseline_identifies_new_and_existing(self):
        baseline_fps = {"fp_aws_key_00001"}
        new_findings, matched = filter_baseline_findings([self.finding1, self.finding2], baseline_fps)
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0].secret_fingerprint, "fp_aws_key_00001")
        self.assertEqual(len(new_findings), 1)
        self.assertEqual(new_findings[0].secret_fingerprint, "fp_gh_token_0002")

    def test_invalid_baseline_handling(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Test missing file
            with self.assertRaises(FileNotFoundError):
                load_baseline(os.path.join(tmpdir, "nonexistent.json"))

            # Test corrupted JSON
            corrupt_file = os.path.join(tmpdir, "corrupt.json")
            with open(corrupt_file, "w") as f:
                f.write("{ invalid json structure")
            with self.assertRaises(ValueError):
                load_baseline(corrupt_file)

            # Test invalid structure (non-dict)
            list_file = os.path.join(tmpdir, "array.json")
            with open(list_file, "w") as f:
                json.dump(["some", "list"], f)
            with self.assertRaises(ValueError):
                load_baseline(list_file)

    def test_duplicate_findings_deduped_in_baseline(self):
        # Passing finding1 twice
        b_dict = generate_baseline_dict([self.finding1, self.finding1], repo_path="/mock/repo")
        self.assertEqual(b_dict["total_findings"], 1)
        self.assertEqual(len(b_dict["fingerprints"]), 1)


class TestBaselineIntegration(unittest.TestCase):
    """
    Tests end-to-end repository scan with baseline generation, code modifications,
    line shifts, and new finding introductions.
    """

    @classmethod
    def setUpClass(cls):
        cls.temp_dir_obj = tempfile.TemporaryDirectory()
        cls.repo_dir = cls.temp_dir_obj.name
        run = lambda *a: subprocess.run(a, cwd=cls.repo_dir, check=True, capture_output=True)
        run("git", "init", "-q")
        run("git", "config", "user.email", "tester@example.com")
        run("git", "config", "user.name", "Tester")

        # Initial commit with fake AWS secret
        with open(os.path.join(cls.repo_dir, "config.py"), "w", encoding="utf-8") as f:
            f.write('AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')
        run("git", "add", ".")
        run("git", "commit", "-q", "-m", "initial commit with aws key")

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir_obj.cleanup()

    def test_baseline_matches_across_line_shifts_and_detects_new_finding(self):
        run = lambda *a: subprocess.run(a, cwd=self.repo_dir, check=True, capture_output=True)

        # Step 1: Scan and generate baseline
        initial_findings = scan_repository(self.repo_dir)
        self.assertEqual(len(initial_findings), 1)
        baseline_path = os.path.join(self.repo_dir, "baseline.json")
        write_baseline(initial_findings, self.repo_dir, baseline_path)

        # Verify baseline filters this finding
        baseline_fps = load_baseline(baseline_path)
        new_f, matched_f = filter_baseline_findings(initial_findings, baseline_fps)
        self.assertEqual(len(new_f), 0)
        self.assertEqual(len(matched_f), 1)

        # Step 2: Add lines above the secret (shifting line number) and introduce a NEW secret
        stripe_val = "sk_" + "live_DUMMYTESTKEYFORSCANNERTEST0000000000000"
        with open(os.path.join(self.repo_dir, "config.py"), "w", encoding="utf-8") as f:
            f.write(
                '# New header comment 1\n'
                '# New header comment 2\n'
                '# New header comment 3\n'
                'AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n'  # Shifted from line 1 to line 4
                f'STRIPE_KEY = "{stripe_val}"\n' # New finding
            )
        run("git", "add", ".")
        run("git", "commit", "-q", "-m", "shift lines and add stripe key")

        updated_findings = scan_repository(self.repo_dir)
        self.assertEqual(len(updated_findings), 2)

        # Verify: old AWS key is matched despite line shift, new Stripe key is flagged as NEW
        new_after_shift, matched_after_shift = filter_baseline_findings(updated_findings, baseline_fps)
        self.assertEqual(len(matched_after_shift), 1)
        self.assertEqual(matched_after_shift[0].rule, "AWS Access Key ID")
        self.assertEqual(len(new_after_shift), 1)
        self.assertEqual(new_after_shift[0].rule, "Stripe Live Secret Key")


if __name__ == "__main__":
    unittest.main()
