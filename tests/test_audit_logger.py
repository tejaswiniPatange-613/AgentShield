
"""Unit tests for AgentShield's structured audit logger."""

import json
import tempfile
import unittest
from pathlib import Path

from agents.audit_logger import AuditLogger


class TestAuditLogger(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_path = Path(self.temp_dir.name) / "audit.log"
        self.logger = AuditLogger(self.log_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def read_events(self):
        return [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
        ]

    def test_writes_valid_json_event(self):
        self.logger.log_event(
            "SECURITY_CHECK_COMPLETED",
            "PASS",
            {"component": "llm_agent", "test_id": "LLM-001"},
        )

        events = self.read_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "SECURITY_CHECK_COMPLETED")
        self.assertEqual(events[0]["outcome"], "PASS")
        self.assertEqual(events[0]["metadata"]["test_id"], "LLM-001")
        self.assertIn("timestamp", events[0])

    def test_appends_multiple_events(self):
        self.logger.log_event("TOOL_ACCESS_BLOCKED", "BLOCKED")
        self.logger.log_event("REDACTION_TRIGGERED", "BLOCKED")

        self.assertEqual(len(self.read_events()), 2)

    def test_rejects_unknown_event(self):
        with self.assertRaises(ValueError):
            self.logger.log_event("UNKNOWN_EVENT")

    def test_rejects_unknown_outcome(self):
        with self.assertRaises(ValueError):
            self.logger.log_event("TOOL_ACCESS_BLOCKED", "SUCCESSFUL")

    def test_sensitive_and_unapproved_metadata_is_omitted(self):
        fake_secret = "AGENTSHIELD-FAKE-SECRET-123"

        self.logger.log_event(
            "REDACTION_TRIGGERED",
            "BLOCKED",
            {
                "component": "llm_agent",
                "secret": fake_secret,
                "prompt": fake_secret,
                "response": fake_secret,
                "custom_message": fake_secret,
                "test_id": "LLM-003",
            },
        )

        raw_log = self.log_path.read_text(encoding="utf-8")
        event = self.read_events()[0]

        self.assertNotIn(fake_secret, raw_log)
        self.assertNotIn("secret", event["metadata"])
        self.assertNotIn("prompt", event["metadata"])
        self.assertNotIn("response", event["metadata"])
        self.assertNotIn("custom_message", event["metadata"])
        self.assertEqual(event["metadata"]["component"], "llm_agent")

    def test_rejects_non_dictionary_metadata(self):
        with self.assertRaises(TypeError):
            self.logger.log_event(
                "SECURITY_CHECK_COMPLETED",
                metadata="do not log this",
            )


if __name__ == "__main__":
    unittest.main()
