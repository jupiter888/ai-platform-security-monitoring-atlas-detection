"""Operator audit identity, correlation, and publication-failure tests."""

import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch
from uuid import uuid4

from fastapi.testclient import TestClient

from src.detection.operator_api import create_app
from src.detection.operator_auth import OperatorAuthenticator


CONFIG = {
    "lab-operator-analyst": {"role": "analyst", "key": "a" * 64},
    "lab-operator-approver": {"role": "approver", "key": "b" * 64},
    "lab-operator-responder": {"role": "responder", "key": "c" * 64},
}


class OperatorAuditTests(unittest.TestCase):
    def setUp(self):
        self.case_id = str(uuid4())
        self.events = []
        self.ledger = Mock()
        self.ledger.open_case.return_value = {
            "case_id": self.case_id,
            "state": "open",
        }
        self.ledger.get.return_value = {
            "case_id": self.case_id,
            "state": "open",
        }

    def client(self, publisher=None):
        def collect(event):
            self.events.append(event)
            return True

        with patch(
            "src.detection.operator_api.ContainmentController"
        ):
            app = create_app(
                authenticator=OperatorAuthenticator(CONFIG),
                ledger=self.ledger,
                audit_publisher=collect if publisher is None else publisher,
            )
        return TestClient(app)

    def headers(self, role="analyst"):
        return {
            "Authorization": (
                f'Bearer {CONFIG[f"lab-operator-{role}"]["key"]}'
            )
        }

    def open_case(self, client, **changes):
        payload = {"finding_id": "d" * 64}
        payload.update(changes)
        return client.post(
            "/cases", headers=self.headers(), json=payload
        )

    def test_unauthenticated_attempt_is_unattributed_and_correlated(self):
        response = self.client().get(f"/cases/{self.case_id}")
        event = self.events[0]
        self.assertEqual(response.status_code, 401)
        self.assertIsNone(event.actor_ref)
        self.assertEqual(event.reason, "authentication_failed")
        self.assertEqual(event.operation, "case_read")
        self.assertEqual(event.request_id, response.headers["X-Request-ID"])

    def test_wrong_role_is_attributed_to_authenticated_operator(self):
        response = self.client().post(
            "/cases",
            headers=self.headers("approver"),
            json={"finding_id": "d" * 64},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.events[0].actor_ref, "lab-operator-approver")
        self.assertEqual(self.events[0].reason, "authorization_denied")
        self.ledger.open_case.assert_not_called()

    def test_successful_creation_carries_server_case_reference(self):
        response = self.open_case(self.client())
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.headers["X-Audit-Delivery"], "buffered")
        self.assertEqual(self.events[0].case_ref, self.case_id)
        self.assertEqual(self.events[0].reason, "operation_succeeded")

    def test_submitted_identity_and_content_are_not_audited(self):
        response = self.open_case(
            self.client(),
            actor="lab-operator-responder",
            secret="submitted-secret-canary",
        )
        self.assertEqual(response.status_code, 400)
        serialized = self.events[0].to_json()
        self.assertNotIn("submitted-secret-canary", serialized)
        self.assertNotIn("lab-operator-responder", serialized)
        self.assertEqual(self.events[0].actor_ref, "lab-operator-analyst")

    def test_failed_publication_preserves_completed_creation(self):
        console = io.StringIO()
        with redirect_stdout(console):
            response = self.open_case(
                self.client(publisher=lambda event: False)
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["case_id"], self.case_id)
        self.assertEqual(response.headers["X-Audit-Delivery"], "unavailable")
        self.ledger.open_case.assert_called_once()
        fallback = json.loads(console.getvalue())
        self.assertEqual(
            fallback["event"], "operator_audit_delivery_failed"
        )
        self.assertEqual(
            fallback["audit_event"]["case_ref"], self.case_id
        )

    def test_publisher_exception_preserves_authentication_rejection(self):
        publisher = Mock(side_effect=RuntimeError("publisher-canary"))
        with redirect_stdout(io.StringIO()):
            response = self.client(publisher).get(
                f"/cases/{self.case_id}"
            )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["X-Audit-Delivery"], "unavailable")
        self.assertNotIn("publisher-canary", response.text)

    def test_case_read_is_audited(self):
        response = self.client().get(
            f"/cases/{self.case_id}", headers=self.headers()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.events[0].operation, "case_read")
        self.assertEqual(self.events[0].case_ref, self.case_id)

    def test_state_conflict_is_distinct_from_role_denial(self):
        self.ledger.open_case.side_effect = ValueError("state-canary")
        response = self.open_case(self.client())
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.events[0].reason, "state_conflict")
        self.assertNotIn("state-canary", self.events[0].to_json())

if __name__ == "__main__":
    unittest.main()