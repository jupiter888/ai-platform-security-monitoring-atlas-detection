"""HTTP authorization and scope checks for containment execution."""

import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from fastapi.testclient import TestClient

from src.detection.operator_api import create_app
from src.detection.operator_auth import OperatorAuthenticator


class OperatorExecutionTests(unittest.TestCase):
    def setUp(self):
        self.case_id = str(uuid4())
        self.configuration = {
            "lab-operator-analyst": {
                "role": "analyst",
                "key": "a" * 64,
            },
            "lab-operator-approver": {
                "role": "approver",
                "key": "b" * 64,
            },
            "lab-operator-responder": {
                "role": "responder",
                "key": "c" * 64,
            },
        }
        self.controller = Mock()
        self.controller.execute.return_value = {
            "case_id": self.case_id,
            "status": "executed",
            "duplicate": False,
        }

        with patch(
            "src.detection.operator_api.ContainmentController",
            return_value=self.controller,
        ):
            app = create_app(
                authenticator=OperatorAuthenticator(self.configuration),
                ledger=Mock(),
                audit_publisher=lambda event: True,
            )

        self.client = TestClient(app)

    def execute(self, key=None, payload=None):
        headers = {}
        if key is not None:
            headers["Authorization"] = f"Bearer {key}"
        return self.client.post(
            f"/cases/{self.case_id}/execute-containment",
            headers=headers,
            json=(
                {"purpose": "controlled_exercise"}
                if payload is None else payload
            ),
        )

    def test_unauthenticated_execution_is_rejected(self):
        self.assertEqual(self.execute().status_code, 401)
        self.controller.execute.assert_not_called()

    def test_analyst_and_approver_cannot_execute(self):
        for key in ("a" * 64, "b" * 64):
            with self.subTest(key_role=key[0]):
                self.assertEqual(self.execute(key).status_code, 403)
        self.controller.execute.assert_not_called()

    def test_responder_cannot_override_scope(self):
        response = self.execute(
            "c" * 64,
            {
                "purpose": "controlled_exercise",
                "caller_ref": "lab-caller-admin",
                "containment_seconds": 3600,
            },
        )
        self.assertEqual(response.status_code, 400)
        self.controller.execute.assert_not_called()

    def test_responder_execution_uses_authenticated_identity(self):
        response = self.execute("c" * 64)

        self.assertEqual(response.status_code, 200)
        case_id, actor = self.controller.execute.call_args.args
        self.assertEqual(case_id, self.case_id)
        self.assertEqual(actor.subject, "lab-operator-responder")
        self.assertEqual(actor.role, "responder")

    def test_controller_rejection_is_sanitized(self):
        self.controller.execute.side_effect = ValueError(
            "private-storage-canary"
        )
        response = self.execute("c" * 64)

        self.assertEqual(response.status_code, 409)
        self.assertNotIn("private-storage-canary", response.text)

if __name__ == "__main__":
    unittest.main()