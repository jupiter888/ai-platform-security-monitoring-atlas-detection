"""
Collector delivery-state tests.
"""

import unittest
from unittest.mock import Mock

from src.telemetry.collector import EventBuffer
from src.telemetry.events import create_event


def event_bytes():
    return create_event(
        provenance="synthetic",
        source="gateway",
        model="research-model",
        reason="authentication_failed",
    ).to_json().encode("utf-8")


class DeliveryTests(unittest.TestCase):
    def test_success_removes_pending_event(self):
        buffer = EventBuffer()
        buffer.submit(event_bytes())
        client = Mock()
        client.send.return_value = True

        self.assertTrue(buffer.deliver_one(client))
        self.assertEqual(len(buffer.events), 0)
        self.assertEqual(buffer.delivered, 1)
        self.assertEqual(buffer.delivery_attempts, 1)

    def test_failure_retains_pending_event(self):
        buffer = EventBuffer()
        raw = event_bytes()
        buffer.submit(raw)
        original = buffer.events[0]
        client = Mock()
        client.send.return_value = False

        self.assertFalse(buffer.deliver_one(client))
        self.assertIs(buffer.events[0], original)
        self.assertEqual(buffer.delivered, 0)
        self.assertEqual(buffer.delivery_failures, 1)

    def test_recovery_resends_same_collected_event(self):
        buffer = EventBuffer()
        buffer.submit(event_bytes())
        client = Mock()
        client.send.side_effect = [False, True]

        self.assertFalse(buffer.deliver_one(client))
        self.assertTrue(buffer.deliver_one(client))

        first = client.send.call_args_list[0].args[0]
        second = client.send.call_args_list[1].args[0]
        self.assertIs(first, second)
        self.assertEqual(buffer.delivery_attempts, 2)
        self.assertEqual(buffer.delivery_failures, 1)
        self.assertEqual(buffer.delivered, 1)

    def test_recently_delivered_event_is_rejected(self):
        buffer = EventBuffer()
        raw = event_bytes()
        buffer.submit(raw)
        client = Mock()
        client.send.return_value = True
        buffer.deliver_one(client)

        self.assertEqual(buffer.submit(raw)[0], 409)
        self.assertEqual(len(buffer.events), 0)

    def test_failure_keeps_capacity_occupied(self):
        buffer = EventBuffer(capacity=1)
        buffer.submit(event_bytes())
        client = Mock()
        client.send.return_value = False
        buffer.deliver_one(client)

        self.assertEqual(buffer.submit(event_bytes())[0], 503)
        self.assertEqual(len(buffer.events), 1)

    def test_unexpected_client_exception_retains_event(self):
        buffer = EventBuffer()
        buffer.submit(event_bytes())
        client = Mock()
        client.send.side_effect = RuntimeError("synthetic-canary")

        self.assertFalse(buffer.deliver_one(client))
        self.assertEqual(len(buffer.events), 1)
        self.assertEqual(buffer.delivery_failures, 1)
        self.assertNotIn("synthetic-canary", buffer.metrics())

    def test_empty_queue_does_not_attempt_delivery(self):
        buffer = EventBuffer()
        client = Mock()

        self.assertIsNone(buffer.deliver_one(client))
        client.send.assert_not_called()
        self.assertEqual(buffer.delivery_attempts, 0)

    def test_recent_id_cache_is_bounded(self):
        buffer = EventBuffer()
        buffer.recent_capacity = 2
        client = Mock()
        client.send.return_value = True

        for _ in range(3):
            buffer.submit(event_bytes())
            buffer.deliver_one(client)

        self.assertEqual(len(buffer.recent_ids), 2)
        self.assertEqual(buffer.delivered, 3)

    def test_ingestion_can_continue_during_delivery(self):
        buffer = EventBuffer()
        buffer.submit(event_bytes())

        def send(_collected):
            status, _ = buffer.submit(event_bytes())
            self.assertEqual(status, 202)
            return True

        client = Mock()
        client.send.side_effect = send

        self.assertTrue(buffer.deliver_one(client))
        self.assertEqual(len(buffer.events), 1)
        self.assertEqual(buffer.accepted, 2)

if __name__ == "__main__":
    unittest.main()