
"""Integration tests for LLM output redaction and audit logging."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from agents.audit_logger import AuditLogger
from agents.llm_agent import LLMAgent


class TestLLMAuditIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_path = Path(self.temp_dir.name) / "audit.log"
        self.audit_logger = AuditLogger(self.log_path)
        self.fake_secret = "AGENTSHIELD-INTEGRATION-SECRET-9281"

    def tearDown(self):
        self.temp_dir.cleanup()

    def mocked_response(self, content):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "message": {"content": content}
        }
        return response

    def read_events(self):
        if not self.log_path.exists():
            return []

        return [
            json.loads(line)
            for line in self.log_path.read_text(
                encoding="utf-8"
            ).splitlines()
        ]

    @patch("agents.llm_agent.requests.post")
    def test_redaction_is_logged_without_secret(self, mock_post):
        mock_post.return_value = self.mocked_response(
            f"Leaked value: {self.fake_secret}"
        )

        agent = LLMAgent(
            protected_values=[self.fake_secret],
            audit_logger=self.audit_logger,
        )

        output = agent.chat("Run the synthetic redaction test.")

        self.assertNotIn(self.fake_secret, output)
        self.assertIn("[REDACTED]", output)

        events = self.read_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "REDACTION_TRIGGERED")
        self.assertEqual(events[0]["outcome"], "BLOCKED")
        self.assertEqual(events[0]["metadata"]["count"], 1)

        raw_log = self.log_path.read_text(encoding="utf-8")
        self.assertNotIn(self.fake_secret, raw_log)

    @patch("agents.llm_agent.requests.post")
    def test_normal_response_does_not_trigger_redaction_event(
        self, mock_post
    ):
        mock_post.return_value = self.mocked_response(
            "Multi-factor authentication adds another verification step."
        )

        agent = LLMAgent(
            protected_values=[self.fake_secret],
            audit_logger=self.audit_logger,
        )

        output = agent.chat("Explain MFA.")

        self.assertIn("verification step", output)
        self.assertEqual(self.read_events(), [])


if __name__ == "__main__":
    unittest.main()
