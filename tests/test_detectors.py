import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secretscanner.entropy import (
    extract_candidate_tokens,
    is_git_commit_reference,
    is_high_entropy_secret,
    looks_like_placeholder,
)
from secretscanner.patterns import PATTERNS
from secretscanner.redact import mask_value, redact_regex_match, redact_token_in_line
from secretscanner.scanner import scan_repository


class TestEntropy(unittest.TestCase):
    def test_low_entropy_words_rejected(self):
        self.assertFalse(is_high_entropy_secret("password"))
        self.assertFalse(is_high_entropy_secret("changeme12345678"))

    def test_placeholder_rejected(self):
        self.assertTrue(looks_like_placeholder("changeme"))
        self.assertTrue(looks_like_placeholder("xxxxxxxxxxxxxxxx"))

    def test_high_entropy_token_accepted(self):
        self.assertTrue(is_high_entropy_secret("qZ8vN2xR7pL4kT9wA1cE6yU3hM0jD5sB8gF2nQ7rV4tX1zC"))

    def test_short_token_rejected_regardless_of_entropy(self):
        self.assertFalse(is_high_entropy_secret("Ax9$kQ"))


class TestRealWorldFalsePositives(unittest.TestCase):
    """
    Regression tests for the false-positive classes found by validating
    against Flask's real commit history (see README's Validation section).
    Without these guards, ~97% of findings on a real repo were noise.
    """

    def test_github_actions_sha_pin_not_flagged(self):
        line = "      - uses: actions/checkout@3d3c1d4c5f8e9a2b1f0e6d7c8a9b0c1d2e3f4567 # v4.1.1"
        self.assertTrue(is_git_commit_reference(line))

    def test_precommit_rev_not_flagged(self):
        line = "  rev: cb8cb0f8b13c0f5b8b8e7c1d2a3b4c5d6e7f8091  # frozen: v0.5.0"
        self.assertTrue(is_git_commit_reference(line))

    def test_submodule_pointer_not_flagged(self):
        line = "Subproject commit 11cbe1af73ea9bee6d81a02b6a7a12b2b7b5a2e4"
        self.assertTrue(is_git_commit_reference(line))

    def test_normal_secret_assignment_not_treated_as_commit_ref(self):
        line = 'INTERNAL_SERVICE_TOKEN = "qZ8vN2xR7pL4kT9wA1cE6yU3hM0jD5sB8gF2nQ7rV4tX1zC"'
        self.assertFalse(is_git_commit_reference(line))

    def test_url_fragment_excluded_from_candidate_tokens(self):
        line = "See <https://github.com/pallets/flask/blob/main/CONTRIBUTING.rst#running-the-testsuite>`_"
        tokens = extract_candidate_tokens(line)
        self.assertEqual(tokens, [])

    def test_real_secret_still_caught_next_to_a_url(self):
        stripe_val = "sk_" + "live_DUMMYTESTKEYFORSCANNERTEST0000000000000"
        line = f'See https://example.com/docs but also STRIPE_KEY="{stripe_val}"'
        tokens = extract_candidate_tokens(line)
        self.assertIn(stripe_val, tokens)


class TestRedaction(unittest.TestCase):
    """
    A prior version of this tool claimed secrets were 'never printed in
    full' but only truncated the surrounding line, leaving the actual
    secret value fully visible. These tests pin down that the fix holds.
    """

    def test_mask_never_contains_full_original_value(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        masked = mask_value(secret)
        self.assertNotEqual(masked, secret)
        self.assertNotIn(secret, masked)

    def test_short_secret_fully_masked(self):
        masked = mask_value("abc123")
        self.assertNotIn("abc123", masked)

    def test_full_mode_redacts_aws_key_from_line(self):
        line = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        for name, severity, confidence, pattern, mode in PATTERNS:
            if name == "AWS Access Key ID":
                m = pattern.search(line)
                redacted = redact_regex_match(line, m, mode)
                self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redacted)
                self.assertIn("AWS_ACCESS_KEY_ID", redacted)  # context preserved
                return
        self.fail("AWS Access Key ID rule not found")

    def test_group_mode_redacts_only_password_not_username_or_host(self):
        line = 'DATABASE_URL = "postgres://admin:Sup3rSecretPass!2024@prod-db.internal:5432/orders"'
        for name, severity, confidence, pattern, mode in PATTERNS:
            if name == "Database Connection String w/ Credentials":
                m = pattern.search(line)
                redacted = redact_regex_match(line, m, mode)
                self.assertNotIn("Sup3rSecretPass!2024", redacted)
                self.assertIn("admin", redacted)              # username kept for context
                self.assertIn("prod-db.internal", redacted)   # host kept for context
                return
        self.fail("Database Connection String rule not found")

    def test_entropy_token_redaction(self):
        token = "qZ8vN2xR7pL4kT9wA1cE6yU3hM0jD5sB8gF2nQ7rV4tX1zC"
        line = f'INTERNAL_SERVICE_TOKEN = "{token}"'
        redacted = redact_token_in_line(line, token)
        self.assertNotIn(token, redacted)
        self.assertIn("INTERNAL_SERVICE_TOKEN", redacted)


class TestLineNumbers(unittest.TestCase):
    """Verifies real line numbers are computed, not left as a placeholder."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir_obj = tempfile.TemporaryDirectory()
        cls.repo_dir = cls.temp_dir_obj.name
        run = lambda *a: subprocess.run(a, cwd=cls.repo_dir, check=True, capture_output=True)
        run("git", "init", "-q")
        run("git", "config", "user.email", "t@example.com")
        run("git", "config", "user.name", "Tester")

        with open(os.path.join(cls.repo_dir, "conf.py"), "w", encoding="utf-8") as f:
            f.write('# line 1 comment\n# line 2 comment\nAWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')
        run("git", "add", ".")
        run("git", "commit", "-q", "-m", "add key on line 3")

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir_obj.cleanup()

    def test_line_number_is_accurate(self):
        findings = scan_repository(self.repo_dir, all_branches=True)
        aws_findings = [f for f in findings if f.rule == "AWS Access Key ID"]
        self.assertEqual(len(aws_findings), 1)
        self.assertEqual(aws_findings[0].line_number, 3)


class TestPatterns(unittest.TestCase):
    def _matches(self, rule_name, text):
        for name, severity, confidence, pattern, redact_mode in PATTERNS:
            if name == rule_name:
                return bool(pattern.search(text))
        raise AssertionError(f"no rule named {rule_name}")

    def test_aws_key_detected(self):
        self.assertTrue(self._matches("AWS Access Key ID", "AKIAIOSFODNN7EXAMPLE"))

    def test_stripe_key_detected(self):
        stripe_val = "sk_" + "live_TESTSCANNERDUMMYFIXTUREKEY0000000000000"
        self.assertTrue(self._matches(
            "Stripe Live Secret Key", f'stripe.api_key = "{stripe_val}"'))

    def test_github_pat_detected(self):
        self.assertTrue(self._matches(
            "GitHub Personal Access Token", 'TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"'))

    def test_private_key_block_detected(self):
        self.assertTrue(self._matches("Private Key Block", "-----BEGIN RSA PRIVATE KEY-----"))

    def test_db_connection_string_detected(self):
        self.assertTrue(self._matches(
            "Database Connection String w/ Credentials",
            'DATABASE_URL = "postgres://admin:Sup3rSecretPass!2024@prod-db.internal:5432/orders"'))

    def test_normal_code_not_flagged(self):
        for name, severity, confidence, pattern, redact_mode in PATTERNS:
            self.assertFalse(pattern.search("def add(a, b):\n    return a + b"),
                              f"false positive on rule {name}")


class TestMultiLineKeyBlock(unittest.TestCase):
    """
    A prior version only flagged the '-----BEGIN...-----' header line and
    dropped the rest of the PEM body - fine for alerting, not for a
    trustworthy fingerprint (the same key re-pasted with a different
    header format, or a different key with an identical header, would
    fingerprint identically). These tests verify the full body is
    captured for fingerprinting while never appearing in the report.
    """

    FAKE_KEY_BODY: list[str] = [
        "MIIEowIBAAKCAQEAxN8FakeKeyMaterialDoNotUseThisIsATestFixtureOnly",
        "b3VsZCBuZXZlciBiZSBhIHJlYWwga2V5IGJvZHkgaW4gYSB0ZXN0IGZpeHR1cmU=",
        "QW5vdGhlciBsaW5lIG9mIGNvbXBsZXRlbHkgZmFrZSBiYXNlNjQgcGF5bG9hZA==",
    ]

    @classmethod
    def setUpClass(cls):
        cls.temp_dir_obj = tempfile.TemporaryDirectory()
        cls.repo_dir = cls.temp_dir_obj.name
        run = lambda *a: subprocess.run(a, cwd=cls.repo_dir, check=True, capture_output=True)
        run("git", "init", "-q")
        run("git", "config", "user.email", "t@example.com")
        run("git", "config", "user.name", "Tester")

        key_lines = (
            ["-----BEGIN RSA PRIVATE KEY-----"] + cls.FAKE_KEY_BODY + ["-----END RSA PRIVATE KEY-----"]
        )
        with open(os.path.join(cls.repo_dir, "id_rsa"), "w", encoding="utf-8") as f:
            f.write("\n".join(key_lines) + "\n")
        run("git", "add", ".")
        run("git", "commit", "-q", "-m", "add private key")

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir_obj.cleanup()

    def test_full_body_captured_and_never_printed_in_preview(self):
        findings = scan_repository(self.repo_dir, all_branches=True)
        key_findings = [f for f in findings if f.rule == "Private Key Block"]
        self.assertEqual(len(key_findings), 1)
        finding = key_findings[0]
        # header + 3 body lines + END marker = 5 lines captured
        self.assertEqual(finding.key_block_lines, 5)
        for body_line in self.FAKE_KEY_BODY:
            self.assertNotIn(body_line, finding.redacted())
            self.assertNotIn(body_line, finding.line_preview)

    def test_fingerprint_reflects_full_body_not_just_header(self):
        # Two different keys with an identical header line must not
        # collide on the same fingerprint.
        findings = scan_repository(self.repo_dir, all_branches=True)
        fp_a = findings[0].secret_fingerprint

        with tempfile.TemporaryDirectory() as other_repo:
            run = lambda *a: subprocess.run(a, cwd=other_repo, check=True, capture_output=True)
            run("git", "init", "-q")
            run("git", "config", "user.email", "t@example.com")
            run("git", "config", "user.name", "Tester")
            different_body = ["ZGlmZmVyZW50IGZha2Uga2V5IGJvZHkgZW50aXJlbHk="]
            with open(os.path.join(other_repo, "id_rsa"), "w", encoding="utf-8") as f:
                f.write("\n".join(["-----BEGIN RSA PRIVATE KEY-----"] + different_body
                                   + ["-----END RSA PRIVATE KEY-----"]) + "\n")
            run("git", "add", ".")
            run("git", "commit", "-q", "-m", "add different key")

            fp_b = scan_repository(other_repo, all_branches=True)[0].secret_fingerprint
            self.assertNotEqual(fp_a, fp_b)


class TestBranchAttribution(unittest.TestCase):
    """
    Verifies findings are labeled with which branch(es) the introducing
    commit is reachable from, so a team can judge blast radius (main vs.
    a stale feature branch) instead of just "somewhere in history".
    """

    @classmethod
    def setUpClass(cls):
        cls.temp_dir_obj = tempfile.TemporaryDirectory()
        cls.repo_dir = cls.temp_dir_obj.name
        run = lambda *a: subprocess.run(a, cwd=cls.repo_dir, check=True, capture_output=True)
        run("git", "init", "-q", "-b", "main")
        run("git", "config", "user.email", "t@example.com")
        run("git", "config", "user.name", "Tester")

        with open(os.path.join(cls.repo_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write("init\n")
        run("git", "add", ".")
        run("git", "commit", "-q", "-m", "init")

        run("git", "checkout", "-q", "-b", "feature/leaky")
        with open(os.path.join(cls.repo_dir, "conf.py"), "w", encoding="utf-8") as f:
            f.write('AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')
        run("git", "add", ".")
        run("git", "commit", "-q", "-m", "add key on feature branch")
        run("git", "checkout", "-q", "main")

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir_obj.cleanup()

    def test_finding_attributed_to_feature_branch_not_main(self):
        findings = scan_repository(self.repo_dir, all_branches=True)
        aws_findings = [f for f in findings if f.rule == "AWS Access Key ID"]
        self.assertEqual(len(aws_findings), 1)
        self.assertIn("feature/leaky", aws_findings[0].branches)
        self.assertNotIn("main", aws_findings[0].branches)

    def test_current_branch_only_scan_tags_current_branch(self):
        findings = scan_repository(self.repo_dir, all_branches=False)
        # on `main`, the feature-branch-only key isn't reachable at all
        aws_findings = [f for f in findings if f.rule == "AWS Access Key ID"]
        self.assertEqual(len(aws_findings), 0)


class TestFullHistoryScan(unittest.TestCase):
    """
    Builds a tiny throwaway git repo where a secret is committed, then
    deleted in a later commit, and verifies the scanner still finds it
    in history and correctly reports it as no longer in HEAD.
    """

    @classmethod
    def setUpClass(cls):
        cls.temp_dir_obj = tempfile.TemporaryDirectory()
        cls.repo_dir = cls.temp_dir_obj.name
        run = lambda *a: subprocess.run(a, cwd=cls.repo_dir, check=True, capture_output=True)
        run("git", "init", "-q")
        run("git", "config", "user.email", "t@example.com")
        run("git", "config", "user.name", "Tester")

        with open(os.path.join(cls.repo_dir, "conf.py"), "w", encoding="utf-8") as f:
            f.write('AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')
        run("git", "add", ".")
        run("git", "commit", "-q", "-m", "add key")

        with open(os.path.join(cls.repo_dir, "conf.py"), "w", encoding="utf-8") as f:
            f.write('AWS_KEY = os.environ["AWS_KEY"]\n')
        run("git", "add", ".")
        run("git", "commit", "-q", "-m", "remove key")

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir_obj.cleanup()

    def test_finds_secret_purged_from_head(self):
        findings = scan_repository(self.repo_dir, all_branches=True)
        aws_findings = [f for f in findings if f.rule == "AWS Access Key ID"]
        self.assertEqual(len(aws_findings), 1)
        self.assertFalse(aws_findings[0].still_in_head)

    def test_deduplicates_repeated_secret(self):
        findings = scan_repository(self.repo_dir, all_branches=True)
        fingerprints = [f.secret_fingerprint for f in findings]
        self.assertEqual(len(fingerprints), len(set(fingerprints)))


if __name__ == "__main__":
    unittest.main()
