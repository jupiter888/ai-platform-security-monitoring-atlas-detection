"""Operator telemetry contract and collector compatibility tests."""

import json
import unittest
from uuid import uuid4

from src.telemetry.events import create_event
from src.telemetry.ingestion import InvalidTelemetry, parse_event
from src.telemetry.loki import encode_payload
from src.telemetry.operator_events import create_operator_event


class OperatorEventTests(unittest.TestCase):
    def payload(self, **changes):
        event = create_operator_event(
            operation="case_read",
            reason="operation_succeeded",
            request_id=str(uuid4()),
            actor_ref="lab-operator-analyst",
            actor_role="analyst",
            case_ref=str(uuid4()),
        )
        payload = json.loads(event.to_json())
        payload.update(changes)
        return payload

    def parse(self, **changes):
        return parse_event(json.dumps(self.payload(**changes)).encode())

    def test_authenticated_event_round_trip(self):
        collected = self.parse()
        self.assertEqual(collected.event.actor_ref, "lab-operator-analyst")
        self.assertEqual(collected.event.source, "operator")
        self.assertIn("collected_at", json.loads(collected.to_json()))

    def test_failed_authentication_remains_unattributed(self):
        event = self.parse(
            reason="authentication_failed",
            outcome="denied",
            actor_ref=None,
            actor_role=None,
        ).event
        self.assertIsNone(event.actor_ref)
        self.assertIsNone(event.actor_role)

    def test_failed_authentication_cannot_claim_identity(self):
        with self.assertRaises(InvalidTelemetry):
            self.parse(reason="authentication_failed", outcome="denied")

    def test_actor_reference_and_role_must_be_paired(self):
        with self.assertRaises(InvalidTelemetry):
            self.parse(actor_role=None)

    def test_unknown_role_is_rejected(self):
        with self.assertRaises(InvalidTelemetry):
            self.parse(actor_role="superuser")

    def test_unknown_operation_is_rejected_without_reflection(self):
        with self.assertRaises(InvalidTelemetry) as caught:
            self.parse(operation="operation-secret-canary")
        self.assertNotIn("operation-secret-canary", str(caught.exception))

    def test_invalid_case_reference_is_rejected(self):
        with self.assertRaises(InvalidTelemetry):
            self.parse(case_ref="untrusted-path-canary")

    def test_timestamp_requires_utc(self):
        for timestamp in (
            "2026-11-14T12:00:00",
            "2026-11-14T12:00:00+01:00",
        ):
            with self.subTest(timestamp=timestamp):
                with self.assertRaises(InvalidTelemetry):
                    self.parse(event_time=timestamp)

    def test_extra_sensitive_fields_are_rejected(self):
        with self.assertRaises(InvalidTelemetry):
            self.parse(prompt="prompt-canary", credential="key-canary")

    def test_loki_labels_separate_operator_events(self):
        payload = json.loads(encode_payload(self.parse()))
        labels = payload["streams"][0]["stream"]
        self.assertEqual(labels, {
            "job": "p10-security",
            "source": "operator",
            "provenance": "live-lab",
        })

    def test_existing_inference_contract_remains_compatible(self):
        event = create_event(
            provenance="live-lab",
            source="gateway",
            model="research-model",
            reason="inference_succeeded",
            caller_ref="lab-caller-reader",
        )
        collected = parse_event(event.to_json().encode())
        self.assertEqual(collected.event.reason, "inference_succeeded")

    def test_decision_consistency_and_success_attribution(self):
        for changes in (
            {"outcome": "denied"},
            {"actor_ref": None, "actor_role": None},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(InvalidTelemetry):
                    self.parse(**changes)

if __name__ == "__main__":
    unittest.main()