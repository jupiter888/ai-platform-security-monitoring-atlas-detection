"""Admission boundaries and release after success or failure."""

import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

from fastapi.testclient import TestClient

from src.inference.admission import AdmissionGate
from src.inference.api import create_app
from src.inference.model import Prediction


READER = "a" * 64
ADMIN = "b" * 64


def prediction():
    return Prediction(
        model="research-model",
        model_version="test-version",
        label="astronomy",
        score=0.7,
    )


class InferenceAdmissionTests(unittest.TestCase):
    def client(self, model=None, publisher=None, checker=None):
        if model is None:
            model = Mock()
            model.predict.return_value = prediction()
        app = create_app(
            credentials={"reader_key": READER, "admin_key": ADMIN},
            model=model,
            publisher=(
                (lambda event: True) if publisher is None else publisher
            ),
            access_checker=(
                (lambda caller, model: False)
                if checker is None else checker
            ),
            admission_limit=1,
        )
        return app, TestClient(app, raise_server_exceptions=False)

    def infer(self, client, key=READER, model="research-model"):
        return client.post(
            "/v1/inference",
            headers={"Authorization": f"Bearer {key}"},
            json={"model": model, "prompt": "admission-input-canary"},
        )

    def test_invalid_limits_are_rejected(self):
        for limit in (0, -1, 9, True, 1.5, "2"):
            with self.subTest(limit=limit):
                with self.assertRaises(ValueError):
                    AdmissionGate(limit)

    def test_default_gate_has_two_nonblocking_slots(self):
        gate = AdmissionGate()
        self.assertTrue(gate.try_acquire())
        self.assertTrue(gate.try_acquire())
        self.assertFalse(gate.try_acquire())
        gate.release()
        gate.release()
        self.assertTrue(gate.try_acquire())
        gate.release()

    def test_pressure_rejects_before_model_and_recovers(self):
        entered = threading.Event()
        release = threading.Event()
        events = []

        def predict(_prompt):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("Test model release timed out")
            return prediction()

        model = Mock()
        model.predict.side_effect = predict

        def publish(event):
            events.append(event)
            return True

        _, client = self.client(model=model, publisher=publish)
        with client, ThreadPoolExecutor(max_workers=1) as pool:
            first = pool.submit(self.infer, client)
            try:
                self.assertTrue(entered.wait(3))
                rejected = self.infer(client)
                self.assertEqual(rejected.status_code, 503)
                self.assertEqual(
                    rejected.json(),
                    {"detail": "Inference capacity unavailable"},
                )
                self.assertEqual(
                    rejected.headers.get("Retry-After"), "1"
                )
                self.assertEqual(model.predict.call_count, 1)
                denial = [
                    event for event in events
                    if event.reason == "concurrency_exceeded"
                ]
                self.assertEqual(len(denial), 1)
                self.assertEqual(
                    denial[0].request_id,
                    rejected.headers["X-Request-ID"],
                )
                self.assertNotIn(
                    "admission-input-canary", denial[0].to_json()
                )
            finally:
                release.set()

            self.assertEqual(first.result(timeout=5).status_code, 200)
            self.assertEqual(self.infer(client).status_code, 200)

    def test_policy_failure_releases_capacity(self):
        checker = Mock(side_effect=[OSError("policy-canary"), False])
        _, client = self.client(checker=checker)
        self.assertEqual(self.infer(client).status_code, 503)
        self.assertEqual(self.infer(client).status_code, 200)

    def test_containment_denial_releases_capacity(self):
        checker = Mock(side_effect=[True, False])
        _, client = self.client(checker=checker)
        self.assertEqual(self.infer(client).status_code, 403)
        self.assertEqual(self.infer(client).status_code, 200)

    def test_telemetry_failure_releases_capacity(self):
        publisher = Mock(side_effect=[False, True])
        _, client = self.client(publisher=publisher)
        self.assertEqual(self.infer(client).status_code, 503)
        self.assertEqual(self.infer(client).status_code, 200)

    def test_model_exception_releases_capacity(self):
        model = Mock()
        model.predict.side_effect = [
            RuntimeError("model-error-canary"),
            prediction(),
        ]
        _, client = self.client(model=model)
        response = self.infer(client)
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("model-error-canary", response.text)
        self.assertEqual(self.infer(client).status_code, 200)

    def test_authentication_and_authorization_precede_admission(self):
        app, client = self.client()
        gate = app.state.admission_gate
        self.assertTrue(gate.try_acquire())
        try:
            self.assertEqual(
                self.infer(client, key="c" * 64).status_code, 401
            )
            self.assertEqual(
                self.infer(client, model="restricted-model").status_code,
                403,
            )
        finally:
            gate.release()

if __name__ == "__main__":
    unittest.main()