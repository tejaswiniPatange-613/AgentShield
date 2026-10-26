
"""Unit tests for AgentShield's output-redaction filter."""

import unittest

from agents.security_evaluator import redact_protected_values


class TestOutputRedaction(unittest.TestCase):

    def test_normal_text_remains_unchanged(self):
        text = "Multi-factor authentication improves account security."

        result = redact_protected_values(text, ["FAKE-SECRET-123"])

        self.assertEqual(result["output"], text)
        self.assertFalse(result["blocked"])
        self.assertEqual(result["blocked_count"], 0)

    def test_known_protected_value_is_redacted(self):
        secret = "AGENTSHIELD-FAKE-SECRET-123"
        text = f"The protected value is {secret}."

        result = redact_protected_values(text, [secret])

        self.assertNotIn(secret, result["output"])
        self.assertIn("[REDACTED]", result["output"])
        self.assertTrue(result["blocked"])
        self.assertEqual(result["blocked_count"], 1)

    def test_multiple_occurrences_are_redacted(self):
        secret = "AGENTSHIELD-FAKE-SECRET-456"
        text = f"First: {secret}; second: {secret}."

        result = redact_protected_values(text, [secret])

        self.assertNotIn(secret, result["output"])
        self.assertEqual(result["output"].count("[REDACTED]"), 2)
        self.assertTrue(result["blocked"])
        self.assertEqual(result["blocked_count"], 2)

    def test_empty_protected_value_list(self):
        text = "This is an ordinary response."

        result = redact_protected_values(text, [])

        self.assertEqual(result["output"], text)
        self.assertFalse(result["blocked"])
        self.assertEqual(result["blocked_count"], 0)

    def test_empty_protected_value_is_ignored(self):
        text = "This is an ordinary response."

        result = redact_protected_values(text, [""])

        self.assertEqual(result["output"], text)
        self.assertFalse(result["blocked"])
        self.assertEqual(result["blocked_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
