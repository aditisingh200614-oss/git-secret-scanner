"""
test_confidence_and_context.py
Tests for multi-factor confidence scoring, context-aware false positive reduction,
and entropy calibration.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secretscanner.entropy import (
    evaluate_entropy_context,
    looks_like_placeholder,
)
from secretscanner.patterns import PATTERNS


class TestConfidenceAndContext(unittest.TestCase):
    def test_vendor_signatures_have_high_confidence(self):
        high_conf_rules = {"AWS Access Key ID", "Stripe Live Secret Key", "GitHub Personal Access Token"}
        for name, severity, confidence, pattern, mode in PATTERNS:
            if name in high_conf_rules:
                self.assertEqual(confidence, "HIGH", f"Rule {name} expected HIGH confidence")

    def test_generic_assignments_have_medium_confidence(self):
        generic_rules = {"Generic API Key Assignment", "Generic Password Assignment", "Generic Secret Assignment"}
        for name, severity, confidence, pattern, mode in PATTERNS:
            if name in generic_rules:
                self.assertEqual(confidence, "MEDIUM", f"Rule {name} expected MEDIUM confidence")

    def test_entropy_with_positive_context_boosts_confidence(self):
        token = "k7P9xL2mQ8vW5zN1rT4yB0cE6uJ3hD"
        line = f'api_key = "{token}"'
        res = evaluate_entropy_context(token, line, file_path="server/app.py")
        self.assertTrue(res["is_secret"])
        self.assertEqual(res["confidence"], "MEDIUM")

    def test_entropy_in_auth_config_file_boosts_to_high_confidence(self):
        token = "k7P9xL2mQ8vW5zN1rT4yB0cE6uJ3hD"
        line = f'JWT_SECRET = "{token}"'
        res = evaluate_entropy_context(token, line, file_path="config/secrets.env")
        self.assertTrue(res["is_secret"])
        self.assertEqual(res["confidence"], "HIGH")

    def test_entropy_in_example_or_doc_context_lowers_confidence(self):
        token = "k7P9xL2mQ8vW5zN1rT4yB0cE6uJ3hD"
        line = f'# Example token for documentation: "{token}"'
        res = evaluate_entropy_context(token, line, file_path="docs/api.md")
        self.assertTrue(res["is_secret"])
        self.assertEqual(res["confidence"], "LOW")
        self.assertIn("example", res["reason"].lower())

    def test_placeholder_patterns_rejected(self):
        placeholders = [
            "changeme",
            "xxxxxxxxxxxxxxxx",
            "123456789012345678",
            "abcdefghijklmnop",
            "<YOUR_API_KEY_HERE>",
            "${API_SECRET}",
        ]
        for p in placeholders:
            self.assertTrue(looks_like_placeholder(p), f"Expected '{p}' to be recognized as placeholder")

    def test_unstructured_entropy_gets_low_confidence(self):
        token = "qZ8vN2xR7pL4kT9wA1cE6yU3hM0jD5sB8gF2nQ7rV4tX1zC"
        line = f'const buffer_id = "{token}";'
        res = evaluate_entropy_context(token, line, file_path="src/render.ts")
        self.assertTrue(res["is_secret"])
        self.assertEqual(res["confidence"], "LOW")


if __name__ == "__main__":
    unittest.main()
