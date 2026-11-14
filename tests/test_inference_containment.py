"""Containment enforcement at the authenticated inference boundary."""

import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from src.inference.api import create_app
from src.inference.model import Prediction


READER_KEY = "a" * 64
ADMIN_KEY = "b" * 64


class InferenceContainmentTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.model = Mock()
        self.model.predict.return_value = Prediction(
            model="research-model",
            model_version="test-version",
            label="astronomy",
            score=0.7,
        )

    def client(self, checker):
        def publish(event):
            self.events.append(event)
            return True

        return TestClient(create_app(
            credentials={
                "reader_key": READER_KEY,
                "admin_key": ADMIN_KEY,
            },
            model=self.model,
            publisher=publish,
            access_checker=checker,
        ))

    def infer(self, client, key=READER_KEY, model="research-model"):
        return client.post(
            "/v1/inference",
            headers={"Authorization": f"Bearer {key}"},
            json={
                "model": model,
                "prompt": "containment-input-canary",
            },
        )

    def test_active_block_prevents_prediction_and_records_decision(self):
        checker = Mock(return_value=True)
        response = self.infer(self.client(checker))

        self.assertEqual(response.status_code, 403)
        self.model.predict.assert_not_called()
        checker.assert_called_once_with(
            "lab-caller-reader", "research-model"
        )
        event = self.events[0]
        self.assertEqual(event.reason, "containment_enforced")
        self.assertEqual(event.outcome, "denied")
        self.assertEqual(
            event.request_id, response.headers["X-Request-ID"]
        )
        self.assertNotIn("containment-input-canary", event.to_json())
        self.assertNotIn("label", response.json())

    def test_scoped_block_does_not_block_other_authorized_pair(self):
        def checker(caller, model):
            return (
                caller == "lab-caller-reader"
                and model == "research-model"
            )

        client = self.client(checker)
        blocked = self.infer(client)
        allowed = self.infer(client, ADMIN_KEY, "restricted-model")

        self.assertEqual(blocked.status_code, 403)
        self.assertEqual(allowed.status_code, 200)
        self.model.predict.assert_called_once()

    def test_policy_failure_prevents_prediction_without_error_leak(self):
        checker = Mock(
            side_effect=OSError("private-policy-path-canary")
        )
        response = self.infer(self.client(checker))

        self.assertEqual(response.status_code, 503)
        self.model.predict.assert_not_called()
        self.assertNotIn("private-policy-path-canary", response.text)
        self.assertNotIn("label", response.json())
        self.assertEqual(
            self.events[0].reason, "response_policy_unavailable"
        )

    def test_non_boolean_policy_result_fails_closed(self):
        response = self.infer(self.client(Mock(return_value=None)))

        self.assertEqual(response.status_code, 503)
        self.model.predict.assert_not_called()

    def test_authorization_denial_precedes_containment_lookup(self):
        checker = Mock(return_value=False)
        response = self.infer(
            self.client(checker),
            READER_KEY,
            "restricted-model",
        )

        self.assertEqual(response.status_code, 403)
        checker.assert_not_called()
        self.model.predict.assert_not_called()
        self.assertEqual(self.events[0].reason, "model_access_denied")

if __name__ == "__main__":
    unittest.main()