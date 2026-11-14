"""Operator publication receipts and safe transport behavior."""

import io
import unittest
from unittest.mock import Mock
from urllib.error import HTTPError, URLError
from uuid import uuid4

from src.telemetry.operator_events import create_operator_event
from src.telemetry.operator_publisher import (
    COLLECTOR_ENDPOINT,
    OperatorPublisher,
)


class OperatorPublisherTests(unittest.TestCase):
    def setUp(self):
        self.event = create_operator_event(
            operation="case_read",
            reason="operation_succeeded",
            request_id=str(uuid4()),
            actor_ref="lab-operator-analyst",
            actor_role="analyst",
            provenance="synthetic",
        )
        self.opener = Mock()

    def response(self, status=202, body=b'{"detail":"Event buffered"}'):
        response = Mock()
        response.status = status
        response.read.return_value = body
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        self.opener.open.return_value = response
        return response

    def test_valid_buffer_receipt_is_accepted(self):
        self.response()
        self.assertTrue(OperatorPublisher(self.opener, producer_key="b" * 64).send(self.event))

    def test_unexpected_status_is_rejected(self):
        self.response(status=200)
        self.assertFalse(OperatorPublisher(self.opener, producer_key="b" * 64).send(self.event))

    def test_invalid_receipts_are_rejected(self):
        for body in (
            b"not-json",
            b"[]",
            b'{"detail":"stored"}',
            b'{"detail":"Event buffered","extra":true}',
        ):
            with self.subTest(body=body):
                self.response(body=body)
                self.assertFalse(
                    OperatorPublisher(self.opener, producer_key="b" * 64).send(self.event)
                )

    def test_oversized_receipt_is_rejected(self):
        response = self.response(body=b"x" * 4097)
        self.assertFalse(OperatorPublisher(self.opener, producer_key="b" * 64).send(self.event))
        response.read.assert_called_once_with(4097)

    def test_transport_failures_return_false(self):
        for error in (
            URLError("transport-canary"),
            OSError("transport-canary"),
        ):
            with self.subTest(error_type=type(error).__name__):
                self.opener.open.side_effect = error
                self.assertFalse(
                    OperatorPublisher(self.opener, producer_key="b" * 64).send(self.event)
                )

    def test_destination_body_and_timeout_are_fixed(self):
        self.response()
        OperatorPublisher(self.opener, producer_key="b" * 64).send(self.event)
        args, kwargs = self.opener.open.call_args
        request = args[0]
        self.assertEqual(request.full_url, COLLECTOR_ENDPOINT)
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.data, self.event.to_json().encode())
        self.assertEqual(
            request.get_header("Authorization"), "Bearer " + "b" * 64
        )
        self.assertEqual(kwargs["timeout"], 2)

    def test_wrong_event_type_is_not_sent(self):
        self.assertFalse(OperatorPublisher(self.opener, producer_key="b" * 64).send({}))
        self.opener.open.assert_not_called()

    def test_http_error_response_is_closed(self):
        stream = io.BytesIO(b"rejected")
        self.opener.open.side_effect = HTTPError(
            COLLECTOR_ENDPOINT, 400, "Rejected", {}, stream
        )
        self.assertFalse(OperatorPublisher(self.opener, producer_key="b" * 64).send(self.event))
        self.assertTrue(stream.closed)

if __name__ == "__main__":
    unittest.main()