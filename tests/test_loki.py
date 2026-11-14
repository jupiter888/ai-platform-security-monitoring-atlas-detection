"""
Loki payload and delivery behavior tests.

Mock transport only; no running Loki instance is required.
"""

import io
import json
import unittest
from dataclasses import replace
from unittest.mock import MagicMock
from urllib.error import HTTPError, URLError

from src.telemetry.events import create_event
from src.telemetry.ingestion import parse_event
from src.telemetry.loki import (
    DELIVERY_TIMEOUT_SECONDS,
    LOKI_ENDPOINT,
    LokiClient,
    NoRedirects,
    collection_timestamp_ns,
    encode_payload,
)


class LokiTests(unittest.TestCase):
    def make_collected(self):
        event = create_event(
            provenance="synthetic",
            source="gateway",
            model="research-model",
            reason="inference_succeeded",
            caller_ref="lab-caller-reader",
        )
        return parse_event(event.to_json().encode("utf-8"))

    def make_client(self, status=204):
        opener = MagicMock()
        response = opener.open.return_value.__enter__.return_value
        response.status = status
        return LokiClient(opener=opener), opener

    def test_http_204_confirms_acceptance(self):
        client, _ = self.make_client()
        self.assertTrue(client.send(self.make_collected()))

    def test_other_success_statuses_do_not_confirm_acceptance(self):
        for status in (200, 201, 202):
            with self.subTest(status=status):
                client, _ = self.make_client(status)
                self.assertFalse(client.send(self.make_collected()))

    def test_http_error_returns_failure(self):
        client, opener = self.make_client()
        opener.open.side_effect = HTTPError(
            LOKI_ENDPOINT,
            500,
            "Synthetic failure",
            {},
            io.BytesIO(b"synthetic-upstream-canary"),
        )
        self.assertFalse(client.send(self.make_collected()))
        self.assertEqual(opener.open.call_count, 1)

    def test_transport_errors_return_failure_without_internal_retry(self):
        for error in (
            URLError("Synthetic connection failure"),
            TimeoutError("Synthetic timeout"),
            ConnectionResetError("Synthetic connection reset"),
        ):
            with self.subTest(error=type(error).__name__):
                client, opener = self.make_client()
                opener.open.side_effect = error

                self.assertFalse(client.send(self.make_collected()))
                self.assertEqual(opener.open.call_count, 1)

    def test_payload_preserves_event_content(self):
        collected = self.make_collected()
        payload = json.loads(encode_payload(collected))
        line = payload["streams"][0]["values"][0][1]

        self.assertEqual(
            json.loads(line),
            json.loads(collected.to_json()),
        )

    def test_stream_labels_are_bounded_metadata_only(self):
        collected = self.make_collected()
        payload = json.loads(encode_payload(collected))
        labels = payload["streams"][0]["stream"]

        self.assertEqual(
            labels,
            {
                "job": "p10-security",
                "source": "gateway",
                "provenance": "synthetic",
            },
        )
        self.assertNotIn("event_id", labels)
        self.assertNotIn("request_id", labels)
        self.assertNotIn("caller_ref", labels)

    def test_stream_timestamp_uses_collection_time(self):
        collected = replace(
            self.make_collected(),
            collected_at="1970-01-01T00:00:01.123456+00:00",
        )
        payload = json.loads(encode_payload(collected))
        timestamp = payload["streams"][0]["values"][0][0]

        self.assertEqual(timestamp, "1123456000")
        self.assertIsInstance(timestamp, str)

    def test_payload_is_stable_between_attempts(self):
        collected = self.make_collected()
        self.assertEqual(
            encode_payload(collected),
            encode_payload(collected),
        )
        self.assertEqual(
            collection_timestamp_ns(collected.collected_at),
            collection_timestamp_ns(collected.collected_at),
        )

    def test_redirect_handler_declines_redirect(self):
        result = NoRedirects().redirect_request(
            None,
            None,
            307,
            "Temporary Redirect",
            {},
            "https://elsewhere.invalid/",
        )
        self.assertIsNone(result)

    def test_fixed_endpoint_timeout_and_no_authorization_header(self):
        client, opener = self.make_client()
        client.send(self.make_collected())

        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, LOKI_ENDPOINT)
        self.assertEqual(request.get_method(), "POST")
        self.assertIsNone(request.get_header("Authorization"))
        self.assertEqual(
            opener.open.call_args.kwargs["timeout"],
            DELIVERY_TIMEOUT_SECONDS,
        )

if __name__ == "__main__":
    unittest.main()