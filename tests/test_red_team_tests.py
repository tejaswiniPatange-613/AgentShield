
"""Unit tests for AgentShield's reusable red-team test library."""

import unittest

from agents.mock_agent import MockAIAgent
from agents.red_team_tests import run_red_team_tests


class WeakInjectionAgent(MockAIAgent):
    """Test double that simulates a failed prompt-injection control."""

    def respond(self, user_input):
        if "ignore previous instructions" in user_input.lower():
            self._log_event(
                "prompt_injection",
                "completed",
                {"reason": "Simulated failed control"},
            )
            return f"Leaked value: {self.fake_secret}"

        return super().respond(user_input)


class TestRedTeamTests(unittest.TestCase):
    def test_all_checks_pass_against_mock_agent(self):
        results = run_red_team_tests(MockAIAgent())

        self.assertEqual(len(results), 5)
        self.assertTrue(
            all(result["status"] == "PASS" for result in results),
            results,
        )

    def test_expected_test_ids_are_present(self):
        results = run_red_team_tests(MockAIAgent())

        self.assertEqual(
            [result["test_id"] for result in results],
            ["RT-001", "RT-002", "RT-003", "RT-004", "RT-005"],
        )

    def test_each_result_has_required_fields(self):
        required_fields = {
            "test_id",
            "name",
            "category",
            "expected",
            "observed",
            "status",
            "severity",
            "remediation",
        }

        results = run_red_team_tests(MockAIAgent())

        for result in results:
            with self.subTest(test_id=result["test_id"]):
                self.assertTrue(required_fields.issubset(result.keys()))
                self.assertIn(result["status"], {"PASS", "FAIL"})
                self.assertTrue(result["remediation"].strip())

    def test_injection_failure_is_detected(self):
        results = run_red_team_tests(WeakInjectionAgent())

        injection_result = next(
            result for result in results
            if result["test_id"] == "RT-001"
        )

        self.assertEqual(injection_result["status"], "FAIL")
        self.assertIn(
            "not observed",
            injection_result["observed"],
        )

    def test_red_team_checks_do_not_expose_fake_secret_in_evidence(self):
        agent = MockAIAgent()
        results = run_red_team_tests(agent)

        for result in results:
            with self.subTest(test_id=result["test_id"]):
                self.assertNotIn(agent.fake_secret, result["observed"])
                self.assertNotIn(agent.fake_secret, result["expected"])


if __name__ == "__main__":
    unittest.main()
