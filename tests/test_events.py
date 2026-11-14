"""
Security event contract tests.
"""

import json
import unittest
from dataclasses import replace
from uuid import uuid4

from src.telemetry.events import create_event


class SecurityEventTests(unittest.TestCase):
    def make_event(self, **overrides):
        values = {
            "provenance": "live-lab",
            "source": "gateway",
            "model": "research-model",
            "reason": "inference_succeeded",
            "caller_ref": "lab-caller-reader",
        }
        values.update(overrides)
        return create_event(**values)

    def test_success_serializes_expected_fields(self):
        payload = json.loads(self.make_event().to_json())

        self.assertEqual(
            set(payload),
            {
                "schema_version",
                "event_id",
                "event_time",
                "provenance",
                "source",
                "request_id",
                "model",
                "outcome",
                "reason",
                "caller_ref",
            },
        )
        self.assertEqual(payload["outcome"], "allowed")

    def test_request_correlation_is_preserved(self):
        request_id = str(uuid4())
        first = self.make_event(request_id=request_id)
        second = self.make_event(
            request_id=request_id,
            source="backend",
        )

        self.assertEqual(first.request_id, second.request_id)
        self.assertNotEqual(first.event_id, second.event_id)

    def test_unauthenticated_event_has_no_caller(self):
        event = self.make_event(
            reason="authentication_failed",
            caller_ref=None,
        )
        self.assertIsNone(event.caller_ref)
        self.assertEqual(event.outcome, "denied")

    def test_unauthenticated_caller_attribution_is_rejected(self):
        with self.assertRaises(ValueError):
            self.make_event(reason="authentication_failed")

    def test_personal_or_arbitrary_caller_references_are_rejected(self):
        for caller in (
            "person@example.test",
            "admin",
            "lab-caller-reader\nforged",
        ):
            with self.subTest(caller=caller):
                with self.assertRaises(ValueError):
                    self.make_event(caller_ref=caller)

    def test_unrecognized_metadata_is_rejected(self):
        cases = (
            {"provenance": "production"},
            {"source": "unknown"},
            {"model": "arbitrary-input"},
            {"reason": "arbitrary-message"},
            {"request_id": "not-a-uuid"},
        )

        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(ValueError):
                    self.make_event(**case)

    def test_inconsistent_outcome_is_rejected(self):
        with self.assertRaises(ValueError):
            replace(self.make_event(), outcome="denied")

    def test_timestamp_requires_utc(self):
        for timestamp in (
            "not-a-date",
            "2026-11-12T12:00:00",
            "2026-11-12T12:00:00+01:00",
        ):
            with self.subTest(timestamp=timestamp):
                with self.assertRaises(ValueError):
                    replace(self.make_event(), event_time=timestamp)

    def test_all_provenance_modes_are_explicit(self):
        for provenance in ("live-lab", "synthetic", "replay"):
            with self.subTest(provenance=provenance):
                payload = json.loads(
                    self.make_event(provenance=provenance).to_json()
                )
                self.assertEqual(payload["provenance"], provenance)

    def test_prompt_and_credential_fields_are_not_accepted(self):
        for field in ("prompt", "token", "service_key"):
            with self.subTest(field=field):
                with self.assertRaises(TypeError):
                    self.make_event(**{field: "synthetic-canary"})

if __name__ == "__main__":
    unittest.main()