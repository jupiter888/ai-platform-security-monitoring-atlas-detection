"""Authentication-rule integration with the continuous evaluator."""

import unittest
from datetime import datetime, timedelta, timezone

from src.detection.monitor import evaluate_rules
from src.detection.store import validate_finding
from src.telemetry.events import create_event
from src.telemetry.ingestion import CollectedEvent


NOW = datetime(2026, 11, 13, 12, tzinfo=timezone.utc)


class AuthenticationMonitorTests(unittest.TestCase):
    def records(self, provenance):
        return [
            CollectedEvent(
                event=create_event(
                    provenance=provenance,
                    source="gateway",
                    model="research-model",
                    reason="authentication_failed",
                ),
                collected_at=(
                    NOW - timedelta(seconds=index + 1)
                ).isoformat(),
            )
            for index in range(5)
        ]

    def test_monitor_returns_valid_unattributed_authentication_finding(self):
        findings = evaluate_rules(
            self.records("live-lab"), as_of=NOW
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["rule_id"], "DET-004")
        self.assertIsNone(finding["caller_ref"])
        self.assertEqual(finding["model"], "not-applicable")
        validate_finding(finding)

    def test_synthetic_failures_do_not_enter_live_detection(self):
        self.assertEqual(
            evaluate_rules(self.records("synthetic"), as_of=NOW),
            [],
        )

if __name__ == "__main__":
    unittest.main()