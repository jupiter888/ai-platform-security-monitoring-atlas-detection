"""Aggregate authentication detection and finding-boundary tests."""

import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.detection.authentication import detect_authentication_failures
from src.detection.cases import Actor, CaseLedger
from src.detection.outbox import FindingOutbox
from src.detection.store import FindingStore, validate_finding
from src.telemetry.events import create_event
from src.telemetry.ingestion import CollectedEvent


NOW = datetime(2026, 11, 13, 12, tzinfo=timezone.utc)


class AuthenticationDetectionTests(unittest.TestCase):
    def records(self, count=5, **changes):
        result = []
        for index in range(count):
            arguments = {
                "provenance": "live-lab",
                "source": "gateway",
                "model": "research-model",
                "reason": "authentication_failed",
            }
            arguments.update(changes)
            result.append(CollectedEvent(
                event=create_event(**arguments),
                collected_at=(
                    NOW - timedelta(seconds=count - index)
                ).isoformat(),
            ))
        return result

    def detect(self, records):
        return detect_authentication_failures(records, as_of=NOW)

    def finding(self):
        return self.detect(self.records())[0]

    def test_four_failures_do_not_trigger(self):
        self.assertEqual(self.detect(self.records(4)), [])

    def test_five_failures_trigger_without_attribution(self):
        finding = self.finding()
        self.assertEqual(finding["rule_id"], "DET-004")
        self.assertEqual(finding["event_count"], 5)
        self.assertIsNone(finding["caller_ref"])
        self.assertEqual(finding["model"], "not-applicable")
        validate_finding(finding)

    def test_requested_models_do_not_split_aggregate(self):
        records = self.records(3)
        records += self.records(2, model="restricted-model")
        self.assertEqual(len(self.detect(records)), 1)

    def test_missing_credentials_are_a_separate_signal(self):
        self.assertEqual(
            self.detect(self.records(reason="authentication_required")),
            [],
        )

    def test_synthetic_replay_and_other_source_excluded(self):
        for changes in (
            {"provenance": "synthetic"},
            {"provenance": "replay"},
            {"source": "backend"},
        ):
            with self.subTest(changes=changes):
                self.assertEqual(
                    self.detect(self.records(**changes)), []
                )

    def test_lower_boundary_and_future_events_excluded(self):
        for timestamp in (
            NOW - timedelta(seconds=60),
            NOW + timedelta(seconds=1),
        ):
            records = self.records()
            records[-1] = replace(
                records[-1], collected_at=timestamp.isoformat()
            )
            self.assertEqual(self.detect(records), [])

    def test_identical_duplicates_do_not_inflate_threshold(self):
        records = self.records(4)
        self.assertEqual(self.detect(records + [records[0]]), [])

    def test_conflicting_duplicate_is_rejected(self):
        records = self.records()
        conflicting = replace(
            records[0], collected_at=NOW.isoformat()
        )
        with self.assertRaises(ValueError):
            self.detect(records + [conflicting])

    def test_evidence_order_is_stable(self):
        records = self.records()
        first = self.detect(records)[0]
        second = self.detect(list(reversed(records)))[0]
        self.assertEqual(first["finding_id"], second["finding_id"])
        self.assertEqual(first["event_ids"], second["event_ids"])

    def test_validator_rejects_invented_identity_or_model_target(self):
        for changes in (
            {"caller_ref": "lab-caller-reader"},
            {"model": "research-model"},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    validate_finding({**self.finding(), **changes})

    def test_store_and_outbox_support_unknown_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding = self.finding()
            store = FindingStore(root / "findings.sqlite3")
            self.assertTrue(store.put(finding))
            self.assertFalse(store.put(finding))
            self.assertIsNone(
                store.get(finding["finding_id"])["finding"]["caller_ref"]
            )

            outbox = FindingOutbox(root / "outbox.sqlite3")
            self.assertEqual(
                outbox.enqueue(finding, as_of=NOW), "queued"
            )
            self.assertEqual(
                outbox.enqueue(finding, as_of=NOW), "duplicate"
            )
            outbox.mark_delivered(finding["finding_id"], as_of=NOW)
            different = self.finding()
            self.assertEqual(
                outbox.enqueue(different, as_of=NOW), "suppressed"
            )

    def test_unattributed_finding_cannot_open_targeted_case(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = FindingStore(root / "findings.sqlite3")
            finding = self.finding()
            store.put(finding)
            ledger = CaseLedger(root / "cases.sqlite3", store)
            with self.assertRaises(ValueError):
                ledger.open_case(
                    finding["finding_id"],
                    Actor("lab-operator-analyst", "analyst"),
                )

if __name__ == "__main__":
    unittest.main()