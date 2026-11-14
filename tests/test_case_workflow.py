"""
Case authorization, separation of duties, persistence, and audit tests.

Synthetic trusted principals; no operator authentication is claimed.
"""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.detection.cases import Actor, CaseLedger
from src.detection.model_access import detect_model_access
from src.detection.store import FindingStore
from src.telemetry.events import create_event
from src.telemetry.ingestion import CollectedEvent


ANALYST = Actor("lab-operator-analyst", "analyst")
APPROVER = Actor("lab-operator-approver", "approver")


def make_finding(caller="lab-caller-reader"):
    now = datetime.now(timezone.utc)
    records = [
        CollectedEvent(
            event=create_event(
                provenance="live-lab",
                source="gateway",
                model="restricted-model",
                reason="model_access_denied",
                caller_ref=caller,
            ),
            collected_at=(now - timedelta(seconds=age)).isoformat(),
        )
        for age in range(1, 6)
    ]
    return detect_model_access(records, as_of=now)[0]


class CaseWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.findings = FindingStore(root / "findings.sqlite3")
        self.path = root / "cases.sqlite3"
        self.ledger = CaseLedger(self.path, self.findings)
        self.finding = make_finding()
        self.findings.put(self.finding)

    def tearDown(self):
        self.directory.cleanup()

    def open_case(self):
        return self.ledger.open_case(
            self.finding["finding_id"], ANALYST
        )

    def test_analyst_opens_case_with_finding_target(self):
        case = self.open_case()
        self.assertEqual(case["state"], "open")
        self.assertEqual(case["finding_id"], self.finding["finding_id"])
        self.assertEqual(case["caller_ref"], "lab-caller-reader")
        self.assertEqual(case["model"], "restricted-model")

    def test_wrong_role_cannot_open_case(self):
        with self.assertRaises(PermissionError):
            self.ledger.open_case(
                self.finding["finding_id"], APPROVER
            )

    def test_duplicate_case_for_same_finding_is_rejected(self):
        self.open_case()
        with self.assertRaises(ValueError):
            self.open_case()

    def test_benign_closure_prevents_containment_request(self):
        case = self.open_case()
        closed = self.ledger.close_benign(case["case_id"], ANALYST)
        self.assertEqual(closed["state"], "closed_benign")

        with self.assertRaises(ValueError):
            self.ledger.request_containment(
                case["case_id"], ANALYST
            )

    def test_request_preserves_original_target(self):
        case = self.open_case()
        requested = self.ledger.request_containment(
            case["case_id"], ANALYST
        )
        self.assertEqual(requested["state"], "containment_requested")
        self.assertEqual(requested["requester"], ANALYST.subject)
        self.assertEqual(requested["caller_ref"], case["caller_ref"])

    def test_requester_cannot_self_approve_under_another_role(self):
        case = self.open_case()
        self.ledger.request_containment(case["case_id"], ANALYST)

        same_subject = Actor(ANALYST.subject, "approver")
        with self.assertRaises(PermissionError):
            self.ledger.approve_containment(
                case["case_id"], same_subject
            )

    def test_approval_cannot_skip_request(self):
        case = self.open_case()

        with self.assertRaises(ValueError):
            self.ledger.approve_containment(
                case["case_id"], APPROVER
            )

        self.assertEqual(len(self.ledger.get(case["case_id"])["audit"]), 1)

    def test_distinct_approver_can_approve_requested_containment(self):
        case = self.open_case()
        self.ledger.request_containment(case["case_id"], ANALYST)
        approved = self.ledger.approve_containment(
            case["case_id"], APPROVER
        )

        self.assertEqual(approved["state"], "containment_approved")
        self.assertEqual(approved["approver"], APPROVER.subject)

    def test_approver_cannot_request_containment(self):
        case = self.open_case()
        with self.assertRaises(PermissionError):
            self.ledger.request_containment(
                case["case_id"], APPROVER
            )

    def test_accepted_transitions_have_ordered_audit_entries(self):
        case = self.open_case()
        self.ledger.request_containment(case["case_id"], ANALYST)
        result = self.ledger.approve_containment(
            case["case_id"], APPROVER
        )

        self.assertEqual(
            [entry["action"] for entry in result["audit"]],
            [
                "case_opened",
                "containment_requested",
                "containment_approved",
            ],
        )
        self.assertEqual(result["audit"][-1]["actor"], APPROVER.subject)

    def test_case_and_audit_survive_reopening(self):
        case = self.open_case()
        self.ledger.close_benign(case["case_id"], ANALYST)

        reopened = CaseLedger(self.path, self.findings)
        stored = reopened.get(case["case_id"])

        self.assertEqual(stored["state"], "closed_benign")
        self.assertEqual(len(stored["audit"]), 2)

    def test_capacity_preserves_existing_cases(self):
        ledger = CaseLedger(self.path, self.findings, capacity=1)
        first = ledger.open_case(self.finding["finding_id"], ANALYST)

        second = make_finding("lab-caller-other")
        self.findings.put(second)

        with self.assertRaises(RuntimeError):
            ledger.open_case(second["finding_id"], ANALYST)

        self.assertEqual(ledger.get(first["case_id"])["state"], "open")

if __name__ == "__main__":
    unittest.main()