"""
Outbox-to-receiver acknowledgement and retry tests.
"""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from src.detection.model_access import detect_model_access
from src.detection.monitor import deliver_pending
from src.detection.outbox import FindingOutbox
from src.telemetry.events import create_event
from src.telemetry.ingestion import CollectedEvent


NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)


def make_finding(caller="lab-caller-reader"):
    records = [
        CollectedEvent(
            event=create_event(
                provenance="live-lab",
                source="gateway",
                model="restricted-model",
                reason="model_access_denied",
                caller_ref=caller,
            ),
            collected_at=(NOW - timedelta(seconds=age)).isoformat(),
        )
        for age in range(1, 6)
    ]
    return detect_model_access(records, as_of=NOW)[0]


def receipt(finding, duplicate=False):
    return {
        "status": "stored",
        "finding_id": finding["finding_id"],
        "duplicate": duplicate,
    }


class OutboxDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "outbox.sqlite3"
        self.outbox = FindingOutbox(self.path)
        self.finding = make_finding()
        self.outbox.enqueue(self.finding, as_of=NOW)

    def tearDown(self):
        self.directory.cleanup()

    def deliver(self, client, **kwargs):
        return deliver_pending(
            self.outbox,
            client,
            clock=lambda: NOW,
            **kwargs,
        )

    def test_valid_receipt_completes_delivery(self):
        client = Mock()
        client.send.return_value = receipt(self.finding)

        result = self.deliver(client)

        self.assertEqual(len(result["accepted"]), 1)
        self.assertEqual(self.outbox.stats()["pending"], 0)
        self.assertEqual(self.outbox.stats()["delivered"], 1)

    def test_failed_delivery_remains_pending(self):
        client = Mock()
        client.send.return_value = None

        result = self.deliver(client)

        self.assertEqual(result["failed"], 1)
        self.assertEqual(self.outbox.pending(), [self.finding])

    def test_wrong_receipt_cannot_complete_delivery(self):
        client = Mock()
        client.send.return_value = {
            "status": "stored",
            "finding_id": "0" * 64,
            "duplicate": False,
        }

        self.assertEqual(self.deliver(client)["failed"], 1)
        self.assertEqual(self.outbox.stats()["pending"], 1)

    def test_client_exception_retains_finding(self):
        client = Mock()
        client.send.side_effect = RuntimeError("synthetic-canary")

        result = self.deliver(client)

        self.assertEqual(result["failed"], 1)
        self.assertEqual(self.outbox.stats()["pending"], 1)

    def test_duplicate_storage_receipt_completes_delivery(self):
        client = Mock()
        client.send.return_value = receipt(
            self.finding,
            duplicate=True,
        )

        self.deliver(client)

        self.assertEqual(self.outbox.stats()["pending"], 0)

    def test_retry_after_reopening_uses_original_finding(self):
        client = Mock()
        client.send.return_value = None
        self.deliver(client)

        self.outbox = FindingOutbox(self.path)
        client.send.return_value = receipt(self.finding)
        self.deliver(client)

        self.assertEqual(client.send.call_count, 2)
        for call in client.send.call_args_list:
            self.assertEqual(call.args[0], self.finding)
        self.assertEqual(self.outbox.stats()["attempts"], 2)

    def test_one_failure_does_not_block_another_group(self):
        other = make_finding("lab-caller-other")
        self.outbox.enqueue(other, as_of=NOW)

        client = Mock()
        client.send.side_effect = lambda finding: (
            None
            if finding["finding_id"] == self.finding["finding_id"]
            else receipt(finding)
        )

        result = self.deliver(client)

        self.assertEqual(result["attempted"], 2)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(len(result["accepted"]), 1)
        self.assertEqual(self.outbox.pending(), [self.finding])

    def test_local_acknowledgement_failure_preserves_pending(self):
        client = Mock()
        client.send.return_value = receipt(self.finding)

        with patch.object(
            self.outbox,
            "mark_delivered",
            side_effect=RuntimeError("Synthetic database failure"),
        ):
            with self.assertRaises(RuntimeError):
                self.deliver(client)

        self.assertEqual(self.outbox.stats()["pending"], 1)

    def test_delivery_batch_limit_is_respected(self):
        self.outbox.enqueue(
            make_finding("lab-caller-other"),
            as_of=NOW,
        )
        client = Mock()
        client.send.side_effect = lambda finding: receipt(finding)

        result = self.deliver(client, limit=1)

        self.assertEqual(result["attempted"], 1)
        self.assertEqual(self.outbox.stats()["pending"], 1)

    def test_empty_outbox_does_not_contact_receiver(self):
        empty = FindingOutbox(
            Path(self.directory.name) / "empty.sqlite3"
        )
        client = Mock()

        result = deliver_pending(
            empty,
            client,
            clock=lambda: NOW,
        )

        self.assertEqual(result["attempted"], 0)
        client.send.assert_not_called()

if __name__ == "__main__":
    unittest.main()