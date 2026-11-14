"""
Operator authentication, role binding, and workflow HTTP tests.
"""

import copy
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from src.detection.cases import CaseLedger
from src.detection.model_access import detect_model_access
from src.detection.operator_api import create_app
from src.detection.operator_auth import OperatorAuthenticator
from src.detection.store import FindingStore
from src.telemetry.events import create_event
from src.telemetry.ingestion import CollectedEvent


CONFIG = {
    "lab-operator-analyst": {"role": "analyst", "key": "a" * 64},
    "lab-operator-approver": {"role": "approver", "key": "b" * 64},
    "lab-operator-responder": {"role": "responder", "key": "c" * 64},
}


class OperatorAPITests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.findings = FindingStore(root / "findings.sqlite3")
        self.ledger = CaseLedger(root / "cases.sqlite3", self.findings)

        now = datetime.now(timezone.utc)
        records = [
            CollectedEvent(
                event=create_event(
                    provenance="live-lab",
                    source="gateway",
                    model="restricted-model",
                    reason="model_access_denied",
                    caller_ref="lab-caller-reader",
                ),
                collected_at=(now - timedelta(seconds=i)).isoformat(),
            )
            for i in range(1, 6)
        ]
        self.finding = detect_model_access(records, as_of=now)[0]
        self.findings.put(self.finding)

        self.client = TestClient(create_app(
            authenticator=OperatorAuthenticator(CONFIG),
            ledger=self.ledger,
            audit_publisher=lambda event: True,
        ))

    def tearDown(self):
        self.client.close()
        self.directory.cleanup()

    def headers(self, role):
        return {
            "Authorization": (
                f'Bearer {CONFIG[f"lab-operator-{role}"]["key"]}'
            )
        }

    def open_case(self):
        response = self.client.post(
            "/cases",
            json={"finding_id": self.finding["finding_id"]},
            headers=self.headers("analyst"),
        )
        self.assertEqual(response.status_code, 201)
        return response.json()["case_id"]

    def test_missing_credential_is_rejected(self):
        response = self.client.get(f"/cases/{uuid4()}")
        self.assertEqual(response.status_code, 401)

    def test_unknown_service_credential_is_rejected(self):
        response = self.client.get(
            f"/cases/{uuid4()}",
            headers={"Authorization": f'Bearer {"d" * 64}'},
        )
        self.assertEqual(response.status_code, 401)

    def test_analyst_opens_case(self):
        case_id = self.open_case()
        self.assertEqual(
            self.ledger.get(case_id)["opened_by"],
            "lab-operator-analyst",
        )

    def test_approver_cannot_open_case(self):
        response = self.client.post(
            "/cases",
            json={"finding_id": self.finding["finding_id"]},
            headers=self.headers("approver"),
        )
        self.assertEqual(response.status_code, 403)

    def test_role_header_cannot_upgrade_analyst(self):
        case_id = self.open_case()
        response = self.client.post(
            f"/cases/{case_id}/approve-containment",
            json={"purpose": "controlled_exercise"},
            headers={
                **self.headers("analyst"),
                "X-Role": "approver",
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_body_actor_claim_is_rejected(self):
        response = self.client.post(
            "/cases",
            json={
                "finding_id": self.finding["finding_id"],
                "actor": "lab-operator-approver",
            },
            headers=self.headers("analyst"),
        )
        self.assertEqual(response.status_code, 400)

    def test_benign_disposition_is_recorded(self):
        case_id = self.open_case()
        response = self.client.post(
            f"/cases/{case_id}/close-benign",
            json={"disposition": "approved_activity"},
            headers=self.headers("analyst"),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["state"], "closed_benign")

    def test_request_and_distinct_approval_are_recorded(self):
        case_id = self.open_case()
        self.client.post(
            f"/cases/{case_id}/request-containment",
            json={"purpose": "controlled_exercise"},
            headers=self.headers("analyst"),
        )
        response = self.client.post(
            f"/cases/{case_id}/approve-containment",
            json={"purpose": "controlled_exercise"},
            headers=self.headers("approver"),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["state"], "containment_approved")
        self.assertNotEqual(
            response.json()["requester"],
            response.json()["approver"],
        )

    def test_approval_cannot_skip_request(self):
        case_id = self.open_case()
        response = self.client.post(
            f"/cases/{case_id}/approve-containment",
            json={"purpose": "controlled_exercise"},
            headers=self.headers("approver"),
        )
        self.assertEqual(response.status_code, 409)

    def test_responder_cannot_approve(self):
        case_id = self.open_case()
        response = self.client.post(
            f"/cases/{case_id}/approve-containment",
            json={"purpose": "controlled_exercise"},
            headers=self.headers("responder"),
        )
        self.assertEqual(response.status_code, 403)

    def test_target_override_is_rejected(self):
        case_id = self.open_case()
        response = self.client.post(
            f"/cases/{case_id}/request-containment",
            json={
                "purpose": "controlled_exercise",
                "caller_ref": "lab-caller-admin",
            },
            headers=self.headers("analyst"),
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.ledger.get(case_id)["state"], "open")

    def test_invalid_body_is_not_reflected(self):
        response = self.client.post(
            "/cases",
            content=b'{"token":"synthetic-secret-canary"}',
            headers={
                **self.headers("analyst"),
                "Content-Type": "application/json",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("synthetic-secret-canary", response.text)

    def test_duplicate_operator_keys_are_rejected(self):
        configuration = copy.deepcopy(CONFIG)
        configuration["lab-operator-approver"]["key"] = "a" * 64
        with self.assertRaises(ValueError):
            OperatorAuthenticator(configuration)

    def test_missing_required_role_is_rejected(self):
        configuration = copy.deepcopy(CONFIG)
        configuration["lab-operator-responder"]["role"] = "analyst"
        with self.assertRaises(ValueError):
            OperatorAuthenticator(configuration)

    def test_receiver_key_cannot_be_reused_for_an_operator(self):
        with self.assertRaises(ValueError):
            OperatorAuthenticator(CONFIG, forbidden_keys=("a" * 64,))

    def test_short_operator_key_is_rejected(self):
        configuration = copy.deepcopy(CONFIG)
        configuration["lab-operator-analyst"]["key"] = "short"
        with self.assertRaises(ValueError):
            OperatorAuthenticator(configuration)

if __name__ == "__main__":
    unittest.main()