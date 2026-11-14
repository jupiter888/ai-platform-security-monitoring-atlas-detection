"""
Finding receiver authentication and persistence tests.
"""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

from fastapi.testclient import TestClient

from src.detection.model_access import detect_model_access
from src.detection.receiver import create_app
from src.detection.store import FindingStore
from src.telemetry.events import create_event
from src.telemetry.ingestion import CollectedEvent


SERVICE_KEY = "a" * 64


def make_finding():
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
            collected_at=(now - timedelta(seconds=age)).isoformat(),
        )
        for age in range(1, 6)
    ]
    return detect_model_access(records, as_of=now)[0]


class FindingReceiverTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = FindingStore(
            Path(self.directory.name) / "findings.sqlite3"
        )
        self.client = TestClient(create_app(
            store=self.store,
            service_key=SERVICE_KEY,
        ))
        self.finding = make_finding()
        self.headers = {
            "Authorization": f"Bearer {SERVICE_KEY}",
        }

    def tearDown(self):
        self.client.close()
        self.directory.cleanup()

    def test_authenticated_finding_is_stored_before_receipt(self):
        response = self.client.post(
            "/findings",
            json=self.finding,
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json(), {
            "status": "stored",
            "finding_id": self.finding["finding_id"],
            "duplicate": False,
        })
        self.assertEqual(self.store.count(), 1)

    def test_repeat_returns_existing_receipt(self):
        self.client.post(
            "/findings", json=self.finding, headers=self.headers
        )
        response = self.client.post(
            "/findings", json=self.finding, headers=self.headers
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["duplicate"])
        self.assertEqual(self.store.count(), 1)

    def test_missing_credential_is_rejected(self):
        response = self.client.post("/findings", json=self.finding)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.store.count(), 0)

    def test_wrong_credential_is_rejected(self):
        response = self.client.post(
            "/findings",
            json=self.finding,
            headers={"Authorization": f'Bearer {"b" * 64}'},
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.store.count(), 0)

    def test_authentication_precedes_json_parsing(self):
        response = self.client.post(
            "/findings",
            content=b"not-json",
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 401)

    def test_invalid_fields_are_not_reflected(self):
        self.finding["token"] = "synthetic-secret-canary"
        response = self.client.post(
            "/findings",
            json=self.finding,
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("synthetic-secret-canary", response.text)

    def test_oversized_body_is_rejected(self):
        response = self.client.post(
            "/findings",
            content=b"x" * 65537,
            headers={
                **self.headers,
                "Content-Type": "application/json",
            },
        )
        self.assertEqual(response.status_code, 413)

    def test_stored_finding_can_be_retrieved_with_authentication(self):
        self.client.post(
            "/findings", json=self.finding, headers=self.headers
        )
        endpoint = f'/findings/{self.finding["finding_id"]}'

        self.assertEqual(
            self.client.get(endpoint).status_code,
            401,
        )
        response = self.client.get(endpoint, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["finding"], self.finding)

    def test_invalid_service_key_fails_configuration(self):
        with self.assertRaises(RuntimeError):
            create_app(store=self.store, service_key="short")

    def test_storage_failure_does_not_return_acceptance(self):
        store = Mock()
        store.put.side_effect = RuntimeError("synthetic-storage-canary")
        client = TestClient(create_app(
            store=store,
            service_key=SERVICE_KEY,
        ))
        try:
            response = client.post(
                "/findings",
                json=self.finding,
                headers=self.headers,
            )
        finally:
            client.close()

        self.assertEqual(response.status_code, 503)
        self.assertNotIn("synthetic-storage-canary", response.text)


if __name__ == "__main__":
    unittest.main()