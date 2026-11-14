"""
Security telemetry ingestion boundary tests.
"""

import json
import unittest

from src.telemetry.events import create_event
from src.telemetry.ingestion import (
    InvalidTelemetry,
    MAX_EVENT_BYTES,
    parse_event,
)


class IngestionTests(unittest.TestCase):
    def make_payload(self):
        event = create_event(
            provenance="synthetic",
            source="gateway",
            model="research-model",
            reason="authentication_failed",
        )
        return json.loads(event.to_json())

    def encode(self, payload):
        return json.dumps(payload).encode("utf-8")

    def test_valid_event_preserves_source_and_adds_collection_time(self):
        payload = self.make_payload()
        collected = parse_event(self.encode(payload))
        output = json.loads(collected.to_json())

        self.assertEqual(output["event_id"], payload["event_id"])
        self.assertEqual(output["event_time"], payload["event_time"])
        self.assertEqual(output["provenance"], "synthetic")
        self.assertIn("collected_at", output)

    def test_sensitive_and_collector_owned_fields_are_rejected(self):
        for field in (
            "prompt",
            "token",
            "service_key",
            "collected_at",
        ):
            with self.subTest(field=field):
                payload = self.make_payload()
                payload[field] = "synthetic-secret-canary"

                with self.assertRaises(InvalidTelemetry) as raised:
                    parse_event(self.encode(payload))

                self.assertNotIn(
                    "synthetic-secret-canary",
                    str(raised.exception),
                )

    def test_missing_field_is_rejected(self):
        payload = self.make_payload()
        del payload["provenance"]

        with self.assertRaises(InvalidTelemetry):
            parse_event(self.encode(payload))

    def test_duplicate_json_key_is_rejected(self):
        raw = self.encode(self.make_payload())
        raw = raw[:-1] + b', "source": "backend"}'

        with self.assertRaises(InvalidTelemetry):
            parse_event(raw)

    def test_invalid_encoding_and_json_are_rejected(self):
        for raw in (b"\xff", b"{invalid", b"NaN", b"[]", b"null"):
            with self.subTest(raw=raw):
                with self.assertRaises(InvalidTelemetry):
                    parse_event(raw)

    def test_event_size_is_bounded(self):
        for raw in (b"", b"x" * (MAX_EVENT_BYTES + 1)):
            with self.subTest(length=len(raw)):
                with self.assertRaises(InvalidTelemetry):
                    parse_event(raw)

    def test_wrong_types_are_rejected(self):
        for value in ([], {}, 1, True):
            with self.subTest(value=value):
                payload = self.make_payload()
                payload["source"] = value

                with self.assertRaises(InvalidTelemetry):
                    parse_event(self.encode(payload))

    def test_untrusted_reason_does_not_appear_in_error(self):
        payload = self.make_payload()
        payload["reason"] = "synthetic-secret-canary"

        with self.assertRaises(InvalidTelemetry) as raised:
            parse_event(self.encode(payload))

        self.assertNotIn(
            "synthetic-secret-canary",
            str(raised.exception),
        )

    def test_provenance_cannot_be_omitted_or_invented(self):
        payload = self.make_payload()
        payload["provenance"] = "production"

        with self.assertRaises(InvalidTelemetry):
            parse_event(self.encode(payload))

    def test_nested_content_is_rejected(self):
        payload = self.make_payload()
        payload["caller_ref"] = {"identity": "lab-caller-reader"}

        with self.assertRaises(InvalidTelemetry):
            parse_event(self.encode(payload))

if __name__ == "__main__":
    unittest.main()