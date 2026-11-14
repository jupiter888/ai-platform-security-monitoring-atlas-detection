"""
Durable outbox, suppression, capacity, and attempt-state tests.
"""

import copy
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.detection.model_access import detect_model_access
from src.detection.outbox import FindingOutbox
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


class FindingOutboxTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "outbox.sqlite3"
        self.outbox = FindingOutbox(self.path)
        self.finding = make_finding()

    def tearDown(self):
        self.directory.cleanup()

    def test_pending_finding_survives_reopening(self):
        self.outbox.enqueue(self.finding, as_of=NOW)
        reopened = FindingOutbox(self.path)

        self.assertEqual(reopened.pending(), [self.finding])

    def test_duplicate_preserves_original_finding(self):
        self.outbox.enqueue(self.finding, as_of=NOW)
        repeated = copy.deepcopy(self.finding)
        repeated["detected_at"] = (
            NOW + timedelta(seconds=5)
        ).isoformat()

        self.assertEqual(
            self.outbox.enqueue(repeated, as_of=NOW),
            "duplicate",
        )
        self.assertEqual(self.outbox.pending(), [self.finding])

    def test_conflicting_duplicate_is_rejected(self):
        self.outbox.enqueue(self.finding, as_of=NOW)
        changed = copy.deepcopy(self.finding)
        changed["first_seen"] = (
            NOW - timedelta(seconds=6)
        ).isoformat()

        with self.assertRaises(ValueError):
            self.outbox.enqueue(changed, as_of=NOW)

    def test_group_has_only_one_pending_finding(self):
        self.outbox.enqueue(self.finding, as_of=NOW)

        self.assertEqual(
            self.outbox.enqueue(make_finding(), as_of=NOW),
            "pending",
        )
        self.assertEqual(self.outbox.pending(), [self.finding])

    def test_distinct_group_can_be_queued(self):
        self.outbox.enqueue(self.finding, as_of=NOW)

        self.assertEqual(
            self.outbox.enqueue(
                make_finding("lab-caller-other"),
                as_of=NOW,
            ),
            "queued",
        )
        self.assertEqual(self.outbox.stats()["pending"], 2)

    def test_capacity_does_not_evict_pending_findings(self):
        outbox = FindingOutbox(self.path, capacity=1)
        outbox.enqueue(self.finding, as_of=NOW)

        with self.assertRaises(RuntimeError):
            outbox.enqueue(
                make_finding("lab-caller-other"),
                as_of=NOW,
            )

        self.assertEqual(outbox.pending(), [self.finding])

    def test_acknowledgement_retains_delivery_history(self):
        self.outbox.enqueue(self.finding, as_of=NOW)
        self.outbox.mark_delivered(
            self.finding["finding_id"],
            as_of=NOW,
        )

        self.assertEqual(self.outbox.pending(), [])
        self.assertEqual(self.outbox.stats()["delivered"], 1)
        self.assertEqual(self.outbox.stats()["records"], 1)

    def test_delivery_cooldown_survives_reopening(self):
        self.outbox.enqueue(self.finding, as_of=NOW)
        self.outbox.mark_delivered(
            self.finding["finding_id"],
            as_of=NOW,
        )
        reopened = FindingOutbox(self.path)

        self.assertEqual(
            reopened.enqueue(
                make_finding(),
                as_of=NOW + timedelta(seconds=5),
            ),
            "suppressed",
        )

    def test_new_finding_allowed_at_cooldown_boundary(self):
        self.outbox.enqueue(self.finding, as_of=NOW)
        self.outbox.mark_delivered(
            self.finding["finding_id"],
            as_of=NOW,
        )

        self.assertEqual(
            self.outbox.enqueue(
                make_finding(),
                as_of=NOW + timedelta(seconds=60),
            ),
            "queued",
        )

    def test_pending_finding_outlives_source_window(self):
        self.outbox.enqueue(self.finding, as_of=NOW)
        reopened = FindingOutbox(self.path)

        self.assertEqual(
            reopened.enqueue(
                make_finding(),
                as_of=NOW + timedelta(hours=1),
            ),
            "pending",
        )
        self.assertEqual(reopened.pending(), [self.finding])

    def test_attempt_count_survives_reopening(self):
        self.outbox.enqueue(self.finding, as_of=NOW)
        self.outbox.record_attempt(
            self.finding["finding_id"],
            as_of=NOW,
        )
        reopened = FindingOutbox(self.path)

        self.assertEqual(reopened.stats()["attempts"], 1)
        self.assertEqual(reopened.stats()["pending"], 1)

    def test_database_permissions_are_private(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

if __name__ == "__main__":
    unittest.main()