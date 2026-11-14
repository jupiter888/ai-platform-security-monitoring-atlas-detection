"""
Scoped execution, expiry, replay, and persistence tests.
"""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.detection.cases import Actor, CaseLedger
from src.detection.containment import (
    ContainmentController,
    read_block_status,
)
from src.detection.model_access import detect_model_access
from src.detection.store import FindingStore
from src.telemetry.events import create_event
from src.telemetry.ingestion import CollectedEvent


NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
ANALYST = Actor("lab-operator-analyst", "analyst")
APPROVER = Actor("lab-operator-approver", "approver")
RESPONDER = Actor("lab-operator-responder", "responder")


class ContainmentTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.store = FindingStore(root / "findings.sqlite3")
        self.ledger = CaseLedger(root / "cases.sqlite3", self.store)
        self.controller = ContainmentController(self.ledger)

    def tearDown(self):
        self.directory.cleanup()

    def create_case(self, approved=True):
        records = [
            CollectedEvent(
                event=create_event(
                    provenance="live-lab",
                    source="gateway",
                    model="research-model",
                    reason="model_access_denied",
                    caller_ref="lab-caller-reader",
                ),
                collected_at=(NOW - timedelta(seconds=i)).isoformat(),
            )
            for i in range(1, 6)
        ]
        finding = detect_model_access(records, as_of=NOW)[0]
        self.store.put(finding)
        case = self.ledger.open_case(finding["finding_id"], ANALYST)

        if approved:
            self.ledger.request_containment(case["case_id"], ANALYST)
            self.ledger.approve_containment(case["case_id"], APPROVER)

        return case["case_id"]

    def execute(self, case_id, actor=RESPONDER, at=NOW):
        return self.controller.execute(case_id, actor, as_of=at)

    def blocked(self, caller="lab-caller-reader",
                model="research-model", at=NOW):
        return read_block_status(
            self.ledger.path, caller, model, as_of=at
        )

    def test_execution_requires_approval(self):
        case_id = self.create_case(approved=False)
        with self.assertRaises(ValueError):
            self.execute(case_id)
        self.assertFalse(self.blocked())

    def test_non_responder_roles_cannot_execute(self):
        case_id = self.create_case()
        for actor in (ANALYST, APPROVER):
            with self.subTest(role=actor.role):
                with self.assertRaises(PermissionError):
                    self.execute(case_id, actor)

    def test_responder_must_be_a_distinct_subject(self):
        case_id = self.create_case()
        same_subject = Actor(ANALYST.subject, "responder")

        with self.assertRaises(PermissionError):
            self.execute(case_id, same_subject)

    def test_execution_is_scoped_and_lasts_sixty_seconds(self):
        case_id = self.create_case()
        receipt = self.execute(case_id)

        self.assertTrue(receipt["active"])
        self.assertEqual(receipt["duration_seconds"], 60)
        self.assertTrue(self.blocked())
        self.assertFalse(self.blocked(caller="lab-caller-admin"))
        self.assertFalse(self.blocked(model="restricted-model"))

    def test_expiry_restores_access_without_cleanup(self):
        case_id = self.create_case()
        self.execute(case_id)

        self.assertTrue(
            self.blocked(at=NOW + timedelta(seconds=59))
        )
        self.assertFalse(
            self.blocked(at=NOW + timedelta(seconds=60))
        )

    def test_replay_does_not_restart_or_extend_block(self):
        case_id = self.create_case()
        first = self.execute(case_id)
        repeated = self.execute(
            case_id,
            at=NOW + timedelta(hours=1),
        )

        self.assertTrue(repeated["duplicate"])
        self.assertFalse(repeated["active"])
        self.assertEqual(first["started_at"], repeated["started_at"])
        self.assertEqual(first["expires_at"], repeated["expires_at"])

    def test_overlapping_containment_is_rejected(self):
        first = self.create_case()
        second = self.create_case()
        self.execute(first)

        with self.assertRaises(ValueError):
            self.execute(second)

        self.assertEqual(
            self.ledger.get(second)["state"],
            "containment_approved",
        )

    def test_execution_survives_controller_reopening(self):
        case_id = self.create_case()
        first = self.execute(case_id)
        reopened = ContainmentController(self.ledger)
        repeated = reopened.execute(
            case_id, RESPONDER,
            as_of=NOW + timedelta(seconds=1),
        )

        self.assertTrue(repeated["duplicate"])
        self.assertEqual(first["expires_at"], repeated["expires_at"])

    def test_execution_updates_case_and_audit(self):
        case_id = self.create_case()
        self.execute(case_id)
        case = self.ledger.get(case_id)

        self.assertEqual(case["state"], "containment_executed")
        self.assertEqual(
            case["audit"][-1]["action"],
            "containment_executed",
        )
        self.assertEqual(
            case["audit"][-1]["actor"],
            RESPONDER.subject,
        )

    def test_missing_policy_database_is_not_an_allow_result(self):
        with self.assertRaises(FileNotFoundError):
            read_block_status(
                Path(self.directory.name) / "missing.sqlite3",
                "lab-caller-reader",
                "research-model",
                as_of=NOW,
            )

if __name__ == "__main__":
    unittest.main()