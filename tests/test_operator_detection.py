"""Privileged-denial detection scope and response restrictions."""

import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from src.detection.cases import Actor, CaseLedger
from src.detection.monitor import evaluate_rules
from src.detection.operator_detection import detect_operator_denials
from src.detection.store import FindingStore, validate_finding
from src.telemetry.ingestion import CollectedEvent
from src.telemetry.operator_events import create_operator_event


NOW = datetime(2026, 11, 14, 12, tzinfo=timezone.utc)


class OperatorDetectionTests(unittest.TestCase):
    def records(self, count=3, **changes):
        arguments = {
            "operation": "containment_approve",
            "reason": "authorization_denied",
            "actor_ref": "lab-operator-analyst",
            "actor_role": "analyst",
            "provenance": "live-lab",
        }
        arguments.update(changes)
        return [
            CollectedEvent(
                event=create_operator_event(
                    request_id=str(uuid4()), **arguments
                ),
                collected_at=(
                    NOW - timedelta(seconds=index + 1)
                ).isoformat(),
            )
            for index in range(count)
        ]

    def detect(self, records):
        return detect_operator_denials(records, as_of=NOW)

    def test_two_denials_do_not_trigger(self):
        self.assertEqual(self.detect(self.records(2)), [])

    def test_three_denials_produce_valid_aggregate_finding(self):
        finding = self.detect(self.records())[0]
        self.assertEqual(finding["rule_id"], "DET-006")
        self.assertIsNone(finding["caller_ref"])
        self.assertEqual(finding["model"], "not-applicable")
        validate_finding(finding)

    def test_noncontainment_operations_do_not_count(self):
        for operation in ("case_open", "case_read", "case_close_benign"):
            with self.subTest(operation=operation):
                self.assertEqual(
                    self.detect(self.records(operation=operation)), []
                )

    def test_nonlive_and_unauthenticated_events_do_not_count(self):
        for changes in (
            {"provenance": "synthetic"},
            {"provenance": "replay"},
            {
                "reason": "authentication_failed",
                "actor_ref": None,
                "actor_role": None,
            },
        ):
            with self.subTest(changes=changes):
                self.assertEqual(self.detect(self.records(**changes)), [])

    def test_duplicate_evidence_is_not_counted_twice(self):
        records = self.records(2)
        self.assertEqual(self.detect(records + [records[0]]), [])
        conflicting = replace(
            records[0], collected_at=NOW.isoformat()
        )
        with self.assertRaises(ValueError):
            self.detect(records + [conflicting])

    def test_finding_persists_but_cannot_open_targeted_case(self):
        finding = self.detect(self.records())[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = FindingStore(root / "findings.sqlite3")
            store.put(finding)
            ledger = CaseLedger(root / "cases.sqlite3", store)
            with self.assertRaises(ValueError):
                ledger.open_case(
                    finding["finding_id"],
                    Actor("lab-operator-analyst", "analyst"),
                )

    def test_monitor_includes_operator_denials(self):
        findings = evaluate_rules(self.records(), as_of=NOW)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "DET-006")

    def test_successful_privileged_operations_do_not_count(self):
        self.assertEqual(
            self.detect(self.records(reason="operation_succeeded")), []
        )

if __name__ == "__main__":
    unittest.main()