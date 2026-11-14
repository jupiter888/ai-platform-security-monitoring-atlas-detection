"""Live timestamp acceptance and historical-fixture separation."""

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from src.telemetry.events import create_event
from src.telemetry.ingestion import CollectedEvent, InvalidTelemetry
from src.telemetry.operator_events import create_operator_event
from src.telemetry.time_policy import validate_live_timestamp


NOW = datetime(2026, 11, 14, 12, tzinfo=timezone.utc)


class TelemetryTimePolicyTests(unittest.TestCase):
    def record(self, age=0, provenance="live-lab", operator=False):
        if operator:
            event = create_operator_event(
                operation="case_read",
                reason="authentication_failed",
                request_id=str(uuid4()),
                provenance=provenance,
            )
        else:
            event = create_event(
                provenance=provenance,
                source="gateway",
                model="research-model",
                reason="authentication_failed",
            )
        event = replace(
            event,
            event_time=(NOW - timedelta(seconds=age)).isoformat(),
        )
        return CollectedEvent(event, NOW.isoformat())

    def test_current_live_event_is_accepted(self):
        validate_live_timestamp(self.record())

    def test_exact_age_boundary_is_accepted(self):
        validate_live_timestamp(self.record(age=300))

    def test_event_beyond_age_boundary_is_rejected(self):
        with self.assertRaises(InvalidTelemetry):
            validate_live_timestamp(self.record(age=300.000001))

    def test_exact_future_boundary_is_accepted(self):
        validate_live_timestamp(self.record(age=-30))

    def test_event_beyond_future_boundary_is_rejected(self):
        with self.assertRaises(InvalidTelemetry):
            validate_live_timestamp(self.record(age=-30.000001))

    def test_explicit_fixtures_are_not_given_live_age_restrictions(self):
        for provenance in ("synthetic", "replay"):
            for age in (86400, -86400):
                with self.subTest(provenance=provenance, age=age):
                    validate_live_timestamp(
                        self.record(age=age, provenance=provenance)
                    )

    def test_operator_events_receive_the_same_live_policy(self):
        validate_live_timestamp(self.record(operator=True))
        with self.assertRaises(InvalidTelemetry):
            validate_live_timestamp(self.record(age=600, operator=True))

    def test_naive_collection_time_is_rejected(self):
        record = replace(
            self.record(), collected_at="2026-11-14T12:00:00"
        )
        with self.assertRaises(InvalidTelemetry):
            validate_live_timestamp(record)

if __name__ == "__main__":
    unittest.main()