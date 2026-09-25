"""
test_cli.py
Unit and integration tests for CLI flags (--baseline, --generate-baseline, --sarif, --fail-on, etc.)
and exit code behavior.
"""

import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestCliIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir_obj = tempfile.TemporaryDirectory()
        cls.repo_dir = cls.temp_dir_obj.name
        run = lambda *a: subprocess.run(a, cwd=cls.repo_dir, check=True, capture_output=True)
        run("git", "init", "-q")
        run("git", "config", "user.email", "ci@example.com")
        run("git", "config", "user.name", "CI Bot")

        # Commit 1: AWS secret (CRITICAL)
        with open(os.path.join(cls.repo_dir, "aws.py"), "w", encoding="utf-8") as f:
            f.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        run("git", "add", ".")
        run("git", "commit", "-q", "-m", "add aws key")

        # Commit 2: Slack token (HIGH)
        with open(os.path.join(cls.repo_dir, "slack.py"), "w", encoding="utf-8") as f:
            f.write('SLACK_TOKEN = "xoxb-fake-slack-token-for-test-scanner-123456789"\n')
        run("git", "add", ".")
        run("git", "commit", "-q", "-m", "add slack token")

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir_obj.cleanup()

    def run_cli(self, args):
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = os.environ.copy()
        env["PYTHONPATH"] = project_root + os.pathsep + env.get("PYTHONPATH", "")
        cmd = [sys.executable, "-m", "secretscanner"] + args
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace", env=env, check=False)

    def test_cli_basic_scan(self):
        res = self.run_cli([self.repo_dir])
        self.assertEqual(res.returncode, 0, f"CLI stderr: {res.stderr}, stdout: {res.stdout}")
        self.assertIn("GIT SECRET LEAK SCANNER", res.stdout)
        self.assertIn("AWS Access Key ID", res.stdout)
        self.assertIn("Slack Token", res.stdout)

    def test_cli_fail_on_threshold(self):
        # Scan with --fail-on CRITICAL -> should fail with exit code 1
        res = self.run_cli([self.repo_dir, "--fail-on", "CRITICAL"])
        self.assertEqual(res.returncode, 1)

        # Scan with --fail-on NONE (or none) -> should succeed with exit code 0
        res = self.run_cli([self.repo_dir, "--fail-on", "none"])
        self.assertEqual(res.returncode, 0)

    def test_cli_generate_and_use_baseline(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline_file = os.path.join(tmpdir, "baseline.json")
            sarif_file = os.path.join(tmpdir, "results.sarif")
            json_file = os.path.join(tmpdir, "results.json")
            html_file = os.path.join(tmpdir, "results.html")

            # Step 1: Generate baseline
            res = self.run_cli([self.repo_dir, "--generate-baseline", baseline_file])
            self.assertEqual(res.returncode, 0)
            self.assertTrue(os.path.exists(baseline_file))

            # Step 2: Run with --baseline and --fail-on CRITICAL
            # Since all current findings are in baseline, active findings = 0, so CI passes (exit code 0)
            res = self.run_cli([
                self.repo_dir,
                "--baseline", baseline_file,
                "--fail-on", "CRITICAL",
                "--sarif", sarif_file,
                "--json", json_file,
                "--html", html_file,
            ])
            self.assertEqual(res.returncode, 0)
            self.assertIn("No new secrets detected", res.stdout)
            self.assertTrue(os.path.exists(sarif_file))
            self.assertTrue(os.path.exists(json_file))
            self.assertTrue(os.path.exists(html_file))

    def test_cli_invalid_repo_error_exit_code(self):
        res = self.run_cli(["/nonexistent/directory/path/here"])
        self.assertEqual(res.returncode, 2)
        self.assertIn("error", res.stderr.lower())


if __name__ == "__main__":
    unittest.main()
