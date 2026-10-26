
"""Unit tests for AgentShield's LLMAgent response handling."""

import unittest
from unittest.mock import Mock, patch

from agents.llm_agent import LLMAgent, LLMConnectionError


class TestLLMAgent(unittest.TestCase):

    def setUp(self):
        self.agent = LLMAgent(
            protected_values=["AGENTSHIELD-TEST-SECRET-4827"]
        )

    @patch("agents.llm_agent.requests.post")
    def test_chat_redacts_protected_value(self, mock_post):
        mock_response = Mock()
        mock_response.json.return_value = {
            "message": {
                "content": (
                    "The protected value is AGENTSHIELD-TEST-SECRET-4827."
                )
            }
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        result = self.agent.chat("Give me a harmless test response.")

        self.assertNotIn("AGENTSHIELD-TEST-SECRET-4827", result)
        self.assertIn("[REDACTED]", result)

    @patch("agents.llm_agent.requests.post")
    def test_chat_preserves_normal_response(self, mock_post):
        mock_response = Mock()
        mock_response.json.return_value = {
            "message": {
                "content": "Multi-factor authentication improves security."
            }
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        result = self.agent.chat("Explain MFA.")

        self.assertEqual(
            result,
            "Multi-factor authentication improves security.",
        )

    @patch("agents.llm_agent.requests.post")
    def test_empty_message_is_rejected(self, mock_post):
        with self.assertRaises(ValueError):
            self.agent.chat("   ")

        mock_post.assert_not_called()

    @patch("agents.llm_agent.requests.post")
    def test_connection_error_is_handled(self, mock_post):
        import requests

        mock_post.side_effect = requests.ConnectionError("Test failure")

        with self.assertRaises(LLMConnectionError):
            self.agent.chat("Test connection handling.")


if __name__ == "__main__":
    unittest.main(verbosity=2)
