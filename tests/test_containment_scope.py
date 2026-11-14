"""
Persisted containment scope and fail-closed approval tests.
"""

import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.detection.cases import Actor, CaseLedger
from src.detection.model_access import detect_model_access
from src.detection.store import FindingStore
from src.telemetry.events import create_event
from src.telemetry.ingestion import CollectedEvent


ANALYST = Actor("lab-operator-analyst", "analyst")
APPROVER = Actor("lab-operator-approver", "approver")


class ContainmentScopeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.path = root / "cases.sqlite3"
        store = FindingStore(root / "findings.sqlite3")

        now = datetime.now(timezone.utc)
        records = [
            CollectedEvent(
                event=create_event(
                    provenance="live-lab",
                    source="gateway",
                    model="research-model",
                    reason="model_access_denied",
                    caller_ref="lab-caller-reader",
                ),
                collected_at=(now - timedelta(seconds=i)).isoformat(),
            )
            for i in range(1, 6)
        ]
        finding = detect_model_access(records, as_of=now)[0]
        store.put(finding)

        self.ledger = CaseLedger(self.path, store)
        self.case = self.ledger.open_case(
            finding["finding_id"], ANALYST
        )

    def tearDown(self):
        self.directory.cleanup()

    def test_new_case_contains_explicit_scope(self):
        self.assertEqual(
            self.case["containment_action"],
            "temporary_model_access_block",
        )
        self.assertEqual(self.case["containment_seconds"], 60)
        self.assertEqual(self.case["containment_policy_version"], "1.0")
        self.assertEqual(self.case["caller_ref"], "lab-caller-reader")
        self.assertEqual(self.case["model"], "research-model")

    def test_approval_preserves_scope(self):
        self.ledger.request_containment(self.case["case_id"], ANALYST)
        approved = self.ledger.approve_containment(
            self.case["case_id"], APPROVER
        )

        self.assertEqual(approved["state"], "containment_approved")
        for field in (
            "containment_action",
            "containment_seconds",
            "containment_policy_version",
            "caller_ref",
            "model",
        ):
            self.assertEqual(approved[field], self.case[field])

    def test_unsupported_scope_cannot_be_approved(self):
        self.ledger.request_containment(self.case["case_id"], ANALYST)

        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                """
                UPDATE cases SET containment_seconds = ?
                WHERE case_id = ?
                """,
                (3600, self.case["case_id"]),
            )
            connection.commit()

        with self.assertRaises(ValueError):
            self.ledger.approve_containment(
                self.case["case_id"], APPROVER
            )

    def test_unscoped_case_cannot_request_containment(self):
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                """
                UPDATE cases
                SET containment_action = NULL,
                    containment_seconds = NULL,
                    containment_policy_version = NULL
                WHERE case_id = ?
                """,
                (self.case["case_id"],),
            )
            connection.commit()

        with self.assertRaises(ValueError):
            self.ledger.request_containment(
                self.case["case_id"], ANALYST
            )

if __name__ == "__main__":
    unittest.main()