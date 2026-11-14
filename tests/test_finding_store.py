"""
Finding persistence, validation, and capacity tests.
"""

import copy
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.detection.model_access import detect_model_access
from src.detection.store import FindingStore
from src.telemetry.events import create_event
from src.telemetry.ingestion import CollectedEvent


NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)


def make_finding(caller="lab-caller-reader"):
    records = [
        CollectedEvent(
            event=create_event(
                provenance="live-lab",
                source="gateway",
                model="restricted-model",
                reason="model_access_denied",
                caller_ref=caller,
            ),
            collected_at=(NOW - timedelta(seconds=age)).isoformat(),
        )
        for age in range(1, 6)
    ]
    return detect_model_access(records, as_of=NOW)[0]


class FindingStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "findings.sqlite3"
        self.store = FindingStore(self.path)

    def tearDown(self):
        self.directory.cleanup()

    def test_finding_round_trip(self):
        finding = make_finding()
        self.assertTrue(self.store.put(finding))
        result = self.store.get(finding["finding_id"])
        self.assertEqual(result["finding"], finding)
        self.assertIn("received_at", result)

    def test_persists_after_store_reopens(self):
        finding = make_finding()
        self.store.put(finding)

        reopened = FindingStore(self.path)
        self.assertEqual(reopened.count(), 1)
        self.assertEqual(
            reopened.get(finding["finding_id"])["finding"],
            finding,
        )

    def test_duplicate_is_not_inserted_again(self):
        finding = make_finding()
        self.store.put(finding)

        self.assertFalse(self.store.put(finding))
        self.assertEqual(self.store.count(), 1)

    def test_repeat_evaluation_preserves_first_record(self):
        finding = make_finding()
        self.store.put(finding)

        repeated = copy.deepcopy(finding)
        repeated["detected_at"] = (
            NOW + timedelta(seconds=5)
        ).isoformat()

        self.assertFalse(self.store.put(repeated))
        self.assertEqual(
            self.store.get(finding["finding_id"])["finding"],
            finding,
        )

    def test_unexpected_sensitive_field_is_rejected(self):
        finding = make_finding()
        finding["token"] = "synthetic-secret-canary"

        with self.assertRaises(ValueError) as raised:
            self.store.put(finding)

        self.assertNotIn("synthetic-secret-canary", str(raised.exception))
        self.assertEqual(self.store.count(), 0)

    def test_modified_identity_is_rejected(self):
        finding = make_finding()
        finding["caller_ref"] = "lab-caller-other"

        with self.assertRaises(ValueError):
            self.store.put(finding)

        self.assertEqual(self.store.count(), 0)

    def test_duplicate_evidence_is_rejected(self):
        finding = make_finding()
        finding["event_ids"][1] = finding["event_ids"][0]

        with self.assertRaises(ValueError):
            self.store.put(finding)

    def test_capacity_does_not_delete_existing_evidence(self):
        store = FindingStore(self.path, capacity=1)
        first = make_finding()
        store.put(first)

        with self.assertRaises(RuntimeError):
            store.put(make_finding(caller="lab-caller-other"))

        self.assertEqual(store.count(), 1)
        self.assertEqual(
            store.get(first["finding_id"])["finding"],
            first,
        )

    def test_database_file_is_private(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

if __name__ == "__main__":
    unittest.main()