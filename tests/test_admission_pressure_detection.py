"""Admission-pressure rule configuration and pipeline integration."""

import unittest
from datetime import datetime, timedelta, timezone

from src.detection.model_access import detect_admission_pressure
from src.detection.monitor import evaluate_rules
from src.detection.store import validate_finding
from src.telemetry.events import create_event
from src.telemetry.ingestion import CollectedEvent


NOW = datetime(2026, 11, 14, 12, tzinfo=timezone.utc)


class AdmissionPressureDetectionTests(unittest.TestCase):
    def records(self, count, **changes):
        arguments = {
            "provenance": "live-lab",
            "source": "gateway",
            "model": "research-model",
            "reason": "concurrency_exceeded",
            "caller_ref": "lab-caller-reader",
        }
        arguments.update(changes)
        return [
            CollectedEvent(
                event=create_event(**arguments),
                collected_at=(
                    NOW - timedelta(seconds=index + 1)
                ).isoformat(),
            )
            for index in range(count)
        ]

    def test_two_rejections_remain_below_threshold(self):
        self.assertEqual(
            detect_admission_pressure(self.records(2), as_of=NOW),
            [],
        )

    def test_three_rejections_produce_valid_targeted_finding(self):
        finding = detect_admission_pressure(
            self.records(3), as_of=NOW
        )[0]
        self.assertEqual(finding["rule_id"], "DET-005")
        self.assertEqual(finding["event_count"], 3)
        self.assertEqual(finding["caller_ref"], "lab-caller-reader")
        self.assertEqual(finding["model"], "research-model")
        validate_finding(finding)

    def test_unrelated_denials_do_not_complete_pressure_threshold(self):
        records = self.records(2)
        records += self.records(
            3, reason="model_access_denied"
        )
        self.assertEqual(
            detect_admission_pressure(records, as_of=NOW),
            [],
        )

    def test_continuous_evaluator_includes_pressure_rule(self):
        findings = evaluate_rules(self.records(3), as_of=NOW)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "DET-005")

if __name__ == "__main__":
    unittest.main()