"""
Receiver client contract and failure-handling tests.
"""

import io
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from urllib.error import HTTPError

from src.detection.model_access import detect_model_access
from src.detection.notification import (
    RECEIVER_ENDPOINT,
    RECEIVER_TIMEOUT_SECONDS,
    ReceiverClient,
)
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


class NotificationTests(unittest.TestCase):
    def setUp(self):
        self.finding = make_finding()
        self.receipt = {
            "status": "stored",
            "finding_id": self.finding["finding_id"],
            "duplicate": False,
        }
        self.opener = MagicMock()
        self.response = (
            self.opener.open.return_value.__enter__.return_value
        )
        self.response.status = 201
        self.response.read.return_value = json.dumps(
            self.receipt
        ).encode("utf-8")

        self.client = ReceiverClient(
            service_key=SERVICE_KEY,
            opener=self.opener,
        )

    def test_valid_new_receipt_is_accepted(self):
        self.assertEqual(
            self.client.send(self.finding),
            self.receipt,
        )

    def test_valid_duplicate_receipt_is_accepted(self):
        self.response.status = 200
        self.receipt["duplicate"] = True
        self.response.read.return_value = json.dumps(
            self.receipt
        ).encode("utf-8")
        self.assertEqual(
            self.client.send(self.finding),
            self.receipt,
        )

    def test_http_errors_do_not_confirm_delivery(self):
        for status in (307, 401, 503):
            with self.subTest(status=status):
                self.opener.open.side_effect = HTTPError(
                    RECEIVER_ENDPOINT,
                    status,
                    "Synthetic failure",
                    {},
                    io.BytesIO(b"synthetic-upstream-canary"),
                )
                self.assertIsNone(self.client.send(self.finding))

    def test_timeout_does_not_confirm_delivery(self):
        self.opener.open.side_effect = TimeoutError("synthetic-canary")
        self.assertIsNone(self.client.send(self.finding))
        self.assertEqual(self.opener.open.call_count, 1)

    def test_wrong_finding_receipt_is_rejected(self):
        self.receipt["finding_id"] = "0" * 64
        self.response.read.return_value = json.dumps(
            self.receipt
        ).encode("utf-8")
        self.assertIsNone(self.client.send(self.finding))

    def test_malformed_json_receipt_is_rejected(self):
        self.response.read.return_value = b"not-json"
        self.assertIsNone(self.client.send(self.finding))

    def test_unexpected_receipt_fields_are_rejected(self):
        self.receipt["extra"] = "synthetic-canary"
        self.response.read.return_value = json.dumps(
            self.receipt
        ).encode("utf-8")
        self.assertIsNone(self.client.send(self.finding))

    def test_inconsistent_duplicate_status_is_rejected(self):
        self.response.status = 200
        self.assertIsNone(self.client.send(self.finding))

    def test_request_uses_fixed_destination_and_timeout(self):
        self.client.send(self.finding)
        request = self.opener.open.call_args.args[0]

        self.assertEqual(request.full_url, RECEIVER_ENDPOINT)
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(
            request.get_header("Authorization"),
            f"Bearer {SERVICE_KEY}",
        )
        self.assertEqual(
            self.opener.open.call_args.kwargs["timeout"],
            RECEIVER_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            json.loads(request.data),
            self.finding,
        )

    def test_invalid_service_key_fails_configuration(self):
        with self.assertRaises(RuntimeError):
            ReceiverClient(service_key="short")

if __name__ == "__main__":
    unittest.main()