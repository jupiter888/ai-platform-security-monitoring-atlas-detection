"""
Authenticated model API and security event tests.
"""

import unittest
from unittest.mock import Mock

from fastapi.testclient import TestClient

from src.inference.api import create_app
from src.inference.model import Prediction


READER_KEY = "a" * 64
ADMIN_KEY = "b" * 64


class InferenceAPITests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.model = Mock()
        self.model.predict.return_value = Prediction(
            model="research-model",
            model_version="test-version",
            label="astronomy",
            score=0.7,
        )

        def publisher(event):
            self.events.append(event)
            return True

        self.client = TestClient(create_app(
            credentials={
                "reader_key": READER_KEY,
                "admin_key": ADMIN_KEY,
            },
            model=self.model,
            publisher=publisher,
            access_checker=lambda caller, model: False,
        ))

    def infer(self, key=None, model="research-model", prompt="Synthetic query"):
        headers = {}
        if key is not None:
            headers["Authorization"] = f"Bearer {key}"

        return self.client.post(
            "/v1/inference",
            json={"model": model, "prompt": prompt},
            headers=headers,
        )

    def test_reader_inference_emits_correlated_live_event(self):
        response = self.infer(READER_KEY)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["label"], "astronomy")
        self.assertEqual(self.events[0].provenance, "live-lab")
        self.assertEqual(self.events[0].caller_ref, "lab-caller-reader")
        self.assertEqual(
            self.events[0].request_id,
            response.headers["X-Request-ID"],
        )
        self.assertNotIn("Synthetic query", self.events[0].to_json())

    def test_missing_credential_does_not_invoke_model(self):
        self.assertEqual(self.infer().status_code, 401)
        self.model.predict.assert_not_called()
        self.assertIsNone(self.events[0].caller_ref)

    def test_wrong_credential_does_not_invoke_model(self):
        self.assertEqual(self.infer("c" * 64).status_code, 401)
        self.model.predict.assert_not_called()
        self.assertEqual(self.events[0].reason, "authentication_failed")

    def test_reader_cannot_access_restricted_model(self):
        response = self.infer(READER_KEY, model="restricted-model")
        self.assertEqual(response.status_code, 403)
        self.model.predict.assert_not_called()
        self.assertEqual(self.events[0].reason, "model_access_denied")

    def test_admin_can_access_restricted_model(self):
        response = self.infer(ADMIN_KEY, model="restricted-model")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["model"], "restricted-model")
        self.assertEqual(self.events[0].caller_ref, "lab-caller-admin")

    def test_unknown_model_is_denied_and_sanitized(self):
        response = self.infer(READER_KEY, model="untrusted-model-canary")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.events[0].model, "unrecognized")
        self.model.predict.assert_not_called()

    def test_invalid_body_is_not_reflected(self):
        response = self.client.post(
            "/v1/inference",
            json={"prompt": "synthetic-secret-canary"},
        )
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("synthetic-secret-canary", response.text)
        self.assertNotIn(
            "synthetic-secret-canary",
            self.events[0].to_json(),
        )

    def test_telemetry_failure_withholds_prediction(self):
        client = TestClient(create_app(
            credentials={
                "reader_key": READER_KEY,
                "admin_key": ADMIN_KEY,
            },
            model=self.model,
            publisher=lambda _event: False,
            access_checker=lambda caller, model: False,
        ))
        response = client.post(
            "/v1/inference",
            headers={"Authorization": f"Bearer {READER_KEY}"},
            json={"model": "research-model", "prompt": "Synthetic query"},
        )

        self.assertEqual(response.status_code, 503)
        self.assertNotIn("label", response.json())

    def test_identical_client_credentials_fail_configuration(self):
        with self.assertRaises(RuntimeError):
            create_app(
                credentials={
                    "reader_key": READER_KEY,
                    "admin_key": READER_KEY,
                },
                model=self.model,
            )

if __name__ == "__main__":
    unittest.main()