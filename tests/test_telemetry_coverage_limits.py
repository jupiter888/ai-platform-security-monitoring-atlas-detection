"""Explicit replay-state limits and collection-time detection semantics."""

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from src.detection.authentication import detect_authentication_failures
from src.telemetry.collector import EventBuffer
from src.telemetry.events import create_event
from src.telemetry.ingestion import CollectedEvent
from src.telemetry.time_policy import validate_live_timestamp


NOW = datetime(2026, 11, 14, 12, tzinfo=timezone.utc)


class TelemetryCoverageLimitTests(unittest.TestCase):
    def raw_event(self):
        return create_event(
            provenance="synthetic",
            source="gateway",
            model="research-model",
            reason="authentication_failed",
        ).to_json().encode()

    def test_new_buffer_does_not_remember_previous_event_ids(self):
        raw = self.raw_event()
        original = EventBuffer()
        self.assertEqual(original.submit(raw)[0], 202)
        self.assertEqual(original.submit(raw)[0], 409)

        replacement = EventBuffer()
        self.assertEqual(replacement.submit(raw)[0], 202)
        # This demonstrates a limitation, not durable replay protection.

    def test_evicted_delivered_id_can_be_accepted_again(self):
        buffer = EventBuffer()
        buffer.recent_capacity = 1
        client = Mock()
        client.send.return_value = True

        first = self.raw_event()
        second = self.raw_event()
        self.assertEqual(buffer.submit(first)[0], 202)
        self.assertTrue(buffer.deliver_one(client))
        self.assertEqual(buffer.submit(second)[0], 202)
        self.assertTrue(buffer.deliver_one(client))

        self.assertEqual(buffer.submit(first)[0], 202)
        # Retention is bounded by ID count, not a durable replay ledger.

    def test_delayed_and_out_of_order_source_times_count_at_collection(self):
        records = []
        source_ages = (120, 20, 200, 10, 90)

        for index, source_age in enumerate(source_ages):
            event = create_event(
                provenance="live-lab",
                source="gateway",
                model="research-model",
                reason="authentication_failed",
            )
            event = replace(
                event,
                event_time=(
                    NOW - timedelta(seconds=source_age)
                ).isoformat(),
            )
            record = CollectedEvent(
                event,
                (NOW - timedelta(seconds=5 - index)).isoformat(),
            )
            validate_live_timestamp(record)
            records.append(record)

        findings = detect_authentication_failures(
            records, as_of=NOW
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["event_count"], 5)
        self.assertEqual(
            findings[0]["first_seen"], records[0].collected_at
        )
        self.assertEqual(
            findings[0]["last_seen"], records[-1].collected_at
        )

    def test_old_collection_records_do_not_enter_current_window(self):
        records = []
        for index in range(5):
            collection_time = NOW - timedelta(seconds=61 + index)
            event = create_event(
                provenance="live-lab",
                source="gateway",
                model="research-model",
                reason="authentication_failed",
            )
            event = replace(
                event,
                event_time=(
                    collection_time - timedelta(seconds=2)
                ).isoformat(),
            )
            record = CollectedEvent(
                event, collection_time.isoformat()
            )
            validate_live_timestamp(record)
            records.append(record)

        self.assertEqual(
            detect_authentication_failures(records, as_of=NOW),
            [],
        )

if __name__ == "__main__":
    unittest.main()