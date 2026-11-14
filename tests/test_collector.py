"""
Collector state & actual HTTP integration tests.
"""

import http.client
import json
import unittest
from threading import Thread

from src.telemetry.collector import CollectorServer, EventBuffer
from src.telemetry.events import create_event
from src.telemetry.producer_auth import ProducerAuthenticator


def event_bytes():
    return create_event(
        provenance="synthetic",
        source="gateway",
        model="research-model",
        reason="authentication_failed",
    ).to_json().encode("utf-8")


class BufferTests(unittest.TestCase):
    def test_duplicate_does_not_add_another_event(self):
        buffer = EventBuffer()
        raw = event_bytes()

        self.assertEqual(buffer.submit(raw)[0], 202)
        self.assertEqual(buffer.submit(raw)[0], 409)
        self.assertEqual(len(buffer.events), 1)
        self.assertEqual(buffer.duplicates, 1)

    def test_capacity_rejects_without_eviction(self):
        buffer = EventBuffer(capacity=1)
        first = event_bytes()

        self.assertEqual(buffer.submit(first)[0], 202)
        self.assertEqual(buffer.submit(event_bytes())[0], 503)
        self.assertEqual(buffer.events[0].event.event_id,
                         json.loads(first)["event_id"])
        self.assertEqual(buffer.full, 1)

    def test_invalid_event_is_not_buffered(self):
        buffer = EventBuffer()

        self.assertEqual(buffer.submit(b'{"token":"canary"}')[0], 400)
        self.assertEqual(len(buffer.events), 0)
        self.assertEqual(buffer.invalid, 1)


class CollectorHTTPTests(unittest.TestCase):
    def setUp(self):
        self.buffer = EventBuffer()
        self.server = CollectorServer(
            ("127.0.0.1", 0),
            self.buffer,
            ProducerAuthenticator({
                "gateway": "a" * 64,
                "operator": "b" * 64,
                "fixture": "c" * 64,
            }),
        )
        self.thread = Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.01},
            daemon=True,
        )
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def request(
        self, method, path, body=None, headers=None, authenticate=True
    ):
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.port,
            timeout=3,
        )
        try:
            connection.request(
                method,
                path,
                body=body,
                headers={
                    **(
                        {"Authorization": "Bearer " + "c" * 64}
                        if method == "POST" and authenticate else {}
                    ),
                    **(headers or {}),
                },
            )
            response = connection.getresponse()
            return response.status, response.read().decode("utf-8")
        finally:
            connection.close()

    def test_health(self):
        status, body = self.request("GET", "/health")

        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"detail": "ok"})

    def test_event_ingestion_and_metrics(self):
        status, _ = self.request(
            "POST",
            "/events",
            event_bytes(),
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 202)

        status, body = self.request("GET", "/metrics")
        self.assertEqual(status, 200)
        self.assertIn("p10_collector_events_accepted_total 1\n", body)
        self.assertIn("p10_collector_buffer_events 1\n", body)

    def test_oversized_body_is_rejected(self):
        status, _ = self.request(
            "POST",
            "/events",
            b"x" * 4097,
            {"Content-Type": "application/json"},
        )

        self.assertEqual(status, 413)
        self.assertEqual(len(self.buffer.events), 0)

    def test_wrong_content_type_is_rejected(self):
        status, _ = self.request(
            "POST",
            "/events",
            event_bytes(),
            {"Content-Type": "text/plain"},
        )

        self.assertEqual(status, 415)

    def test_sensitive_input_is_not_reflected(self):
        status, body = self.request(
            "POST",
            "/events",
            b'{"token":"synthetic-secret-canary"}',
            {"Content-Type": "application/json"},
        )

        self.assertEqual(status, 400)
        self.assertNotIn("synthetic-secret-canary", body)


    def test_missing_producer_credential_is_rejected(self):
        status, _ = self.request(
            "POST", "/events", event_bytes(),
            {"Content-Type": "application/json"},
            authenticate=False,
        )
        self.assertEqual(status, 401)
        self.assertEqual(len(self.buffer.events), 0)
        self.assertEqual(self.buffer.producer_unauthorized, 1)

    def test_unknown_producer_credential_is_rejected(self):
        status, _ = self.request(
            "POST", "/events", event_bytes(),
            {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + "d" * 64,
            },
        )
        self.assertEqual(status, 401)
        self.assertEqual(len(self.buffer.events), 0)

    def test_fixture_cannot_submit_live_gateway_event(self):
        raw = create_event(
            provenance="live-lab", source="gateway",
            model="research-model", reason="authentication_failed",
        ).to_json().encode()
        status, _ = self.request(
            "POST", "/events", raw,
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(len(self.buffer.events), 0)
        self.assertEqual(self.buffer.producer_forbidden, 1)

    def test_gateway_producer_can_submit_live_gateway_event(self):
        raw = create_event(
            provenance="live-lab", source="gateway",
            model="research-model", reason="authentication_failed",
        ).to_json().encode()
        status, _ = self.request(
            "POST", "/events", raw,
            {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + "a" * 64,
            },
        )
        self.assertEqual(status, 202)

    def test_gateway_producer_cannot_claim_operator_source(self):
        from uuid import uuid4
        from src.telemetry.operator_events import create_operator_event

        raw = create_operator_event(
            operation="case_read",
            reason="authentication_failed",
            request_id=str(uuid4()),
        ).to_json().encode()
        status, _ = self.request(
            "POST", "/events", raw,
            {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + "a" * 64,
            },
        )
        self.assertEqual(status, 403)
        self.assertEqual(len(self.buffer.events), 0)

    def test_operator_producer_can_submit_operator_event(self):
        from uuid import uuid4
        from src.telemetry.operator_events import create_operator_event

        raw = create_operator_event(
            operation="case_read",
            reason="authentication_failed",
            request_id=str(uuid4()),
        ).to_json().encode()
        status, _ = self.request(
            "POST", "/events", raw,
            {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + "b" * 64,
            },
        )
        self.assertEqual(status, 202)

    def test_duplicate_authorization_headers_are_rejected(self):
        raw = event_bytes()
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=3
        )
        try:
            connection.putrequest("POST", "/events")
            connection.putheader("Authorization", "Bearer " + "c" * 64)
            connection.putheader("Authorization", "Bearer " + "c" * 64)
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", str(len(raw)))
            connection.endheaders(raw)
            response = connection.getresponse()
            self.assertEqual(response.status, 401)
            response.read()
        finally:
            connection.close()
        self.assertEqual(len(self.buffer.events), 0)


    def live_event_at_offset(self, offset):
        from dataclasses import replace
        from datetime import datetime, timedelta, timezone

        event = create_event(
            provenance="live-lab", source="gateway",
            model="research-model", reason="authentication_failed",
        )
        event = replace(
            event,
            event_time=(
                datetime.now(timezone.utc) + timedelta(seconds=offset)
            ).isoformat(),
        )
        return event.to_json().encode()

    def test_stale_live_event_is_rejected_over_http(self):
        status, _ = self.request(
            "POST", "/events", self.live_event_at_offset(-600),
            {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + "a" * 64,
            },
        )
        self.assertEqual(status, 400)
        self.assertEqual(len(self.buffer.events), 0)

    def test_future_live_event_is_rejected_over_http(self):
        status, _ = self.request(
            "POST", "/events", self.live_event_at_offset(120),
            {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + "a" * 64,
            },
        )
        self.assertEqual(status, 400)
        self.assertEqual(len(self.buffer.events), 0)

    def test_unknown_route(self):
        status, _ = self.request("GET", "/unknown")
        self.assertEqual(status, 404)

if __name__ == "__main__":
    unittest.main()