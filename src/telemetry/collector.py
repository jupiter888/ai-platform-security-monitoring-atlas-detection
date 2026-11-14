"""
Project 10 — Local telemetry collector with Loki delivery.

- Strict event validation.
- Bounded in-memory pending buffer.
- Pending and recently delivered event-ID deduplication.
- Background delivery with failed-event retention.
- Prometheus-format ingestion and delivery metrics.
- Loopback-only HTTP listener.

Pending events and duplicate state are lost on process termination.
Not intended as an Internet-facing HTTP server.
"""

import json
from pathlib import Path
from collections import OrderedDict, deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Event, Lock, Thread

from src.telemetry.ingestion import (
    InvalidTelemetry,
    MAX_EVENT_BYTES,
    parse_event,
    unique_object,
)
from src.telemetry.loki import LokiClient
from src.telemetry.producer_auth import ProducerAuthenticator
from src.telemetry.time_policy import validate_live_timestamp


class EventBuffer:
    def __init__(self, capacity=256):
        if type(capacity) is not int or capacity < 1:
            raise ValueError("Capacity must be a positive integer")

        self.capacity = capacity
        self.events = deque()
        self.event_ids = set()
        self.recent_ids = OrderedDict()
        self.recent_capacity = 1024

        self.lock = Lock()
        self.delivery_lock = Lock()

        self.producer_unauthorized = 0
        self.producer_forbidden = 0
        self.accepted = 0
        self.invalid = 0
        self.duplicates = 0
        self.full = 0
        self.delivery_attempts = 0
        self.delivery_failures = 0
        self.delivered = 0

    def reject_producer(self, *, forbidden=False):
        with self.lock:
            if forbidden:
                self.producer_forbidden += 1
            else:
                self.producer_unauthorized += 1

    def reject(self):
        with self.lock:
            self.invalid += 1

    def submit(self, raw):
        try:
            collected = parse_event(raw)
        except InvalidTelemetry:
            self.reject()
            return 400, "Invalid telemetry"

        return self.submit_collected(collected)

    def submit_collected(self, collected):
        with self.lock:
            event_id = collected.event.event_id

            if event_id in self.event_ids or event_id in self.recent_ids:
                self.duplicates += 1
                return 409, "Duplicate event"

            if len(self.events) >= self.capacity:
                self.full += 1
                return 503, "Telemetry buffer full"

            self.events.append(collected)
            self.event_ids.add(event_id)
            self.accepted += 1

        return 202, "Event buffered"

    def deliver_one(self, client):
        # Serialize delivery so two workers cannot send the queue head
        # simultaneously. Ingestion does not acquire this lock.
        with self.delivery_lock:
            with self.lock:
                if not self.events:
                    return None

                collected = self.events[0]
                self.delivery_attempts += 1

            # Network I/O must not hold the ingestion/metrics lock.
            try:
                accepted = client.send(collected) is True
            except Exception:
                # Retain the event and expose the failure numerically.
                # Do not serialize exceptions or upstream response bodies.
                accepted = False

            with self.lock:
                if not accepted:
                    self.delivery_failures += 1
                    return False

                self.events.popleft()
                event_id = collected.event.event_id
                self.event_ids.remove(event_id)

                self.recent_ids[event_id] = None
                while len(self.recent_ids) > self.recent_capacity:
                    self.recent_ids.popitem(last=False)

                self.delivered += 1
                return True

    def metrics(self):
        with self.lock:
            values = {
                "p10_collector_producer_unauthorized_total": (
                    "counter", self.producer_unauthorized
                ),
                "p10_collector_producer_forbidden_total": (
                    "counter", self.producer_forbidden
                ),
                "p10_collector_events_accepted_total": (
                    "counter", self.accepted
                ),
                "p10_collector_events_invalid_total": (
                    "counter", self.invalid
                ),
                "p10_collector_events_duplicate_total": (
                    "counter", self.duplicates
                ),
                "p10_collector_events_buffer_full_total": (
                    "counter", self.full
                ),
                "p10_collector_buffer_events": (
                    "gauge", len(self.events)
                ),
                "p10_collector_buffer_capacity": (
                    "gauge", self.capacity
                ),
                "p10_collector_delivery_attempts_total": (
                    "counter", self.delivery_attempts
                ),
                "p10_collector_delivery_failures_total": (
                    "counter", self.delivery_failures
                ),
                "p10_collector_events_delivered_total": (
                    "counter", self.delivered
                ),
                "p10_collector_recent_event_ids": (
                    "gauge", len(self.recent_ids)
                ),
            }

        lines = []
        for name, (metric_type, value) in values.items():
            lines.append(f"# TYPE {name} {metric_type}")
            lines.append(f"{name} {value}")

        return "\n".join(lines) + "\n"


class DeliveryWorker:
    def __init__(self, buffer, client):
        self.buffer = buffer
        self.client = client
        self.stop_event = Event()
        self.thread = Thread(
            target=self.run,
            name="loki-delivery",
            daemon=True,
        )

    def start(self):
        self.thread.start()

    def run(self):
        while not self.stop_event.is_set():
            result = self.buffer.deliver_one(self.client)

            # Retry a failed queue head after two seconds.
            # Empty and successful iterations wait briefly.
            delay = 2.0 if result is False else 0.2
            self.stop_event.wait(delay)

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=5)


class CollectorServer(HTTPServer):
    def __init__(self, address, buffer, authenticator):
        if not isinstance(authenticator, ProducerAuthenticator):
            raise ValueError("Producer authenticator is required")
        self.authenticator = authenticator
        self.buffer = buffer
        super().__init__(address, CollectorHandler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(3)
        return connection, address


class CollectorHandler(BaseHTTPRequestHandler):
    server_version = "Project10Collector"
    sys_version = ""

    def log_message(self, _format, *args):
        # Default access logs may include untrusted request text.
        pass

    def reply(self, status, message):
        body = json.dumps({"detail": message}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.reply(200, "ok")
            return

        if self.path == "/metrics":
            body = self.server.buffer.metrics().encode("utf-8")
            self.send_response(200)
            self.send_header(
                "Content-Type",
                "text/plain; version=0.0.4; charset=utf-8",
            )
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return

        self.reply(404, "Not found")

    def do_POST(self):
        if self.path != "/events":
            self.reply(404, "Not found")
            return

        producer = self.server.authenticator.authenticate(
            self.headers.get_all("Authorization") or []
        )
        if producer is None:
            self.server.buffer.reject_producer()
            self.reply(401, "Producer authentication failed")
            return

        def reject(status, message):
            self.server.buffer.reject()
            self.reply(status, message)

        if self.headers.get_all("Transfer-Encoding"):
            reject(400, "Unsupported transfer encoding")
            return

        lengths = self.headers.get_all("Content-Length") or []
        if (
            len(lengths) != 1
            or not lengths[0].isascii()
            or not lengths[0].isdigit()
            or len(lengths[0]) > 10
        ):
            reject(400, "Invalid content length")
            return

        size = int(lengths[0])
        if not 0 < size <= MAX_EVENT_BYTES:
            reject(413, "Invalid telemetry size")
            return

        content_types = self.headers.get_all("Content-Type") or []
        if (
            len(content_types) != 1
            or content_types[0].strip().lower() != "application/json"
        ):
            reject(415, "Content type must be application/json")
            return

        try:
            raw = self.rfile.read(size)
        except OSError:
            reject(408, "Request body timeout")
            return

        if len(raw) != size:
            reject(400, "Incomplete request body")
            return

        try:
            collected = parse_event(raw)
        except InvalidTelemetry:
            reject(400, "Invalid telemetry")
            return

        if not self.server.authenticator.permits(producer, collected.event):
            self.server.buffer.reject_producer(forbidden=True)
            self.reply(403, "Producer authorization denied")
            return

        try:
            validate_live_timestamp(collected)
        except InvalidTelemetry:
            reject(400, "Invalid telemetry")
            return

        status, message = self.server.buffer.submit_collected(collected)
        self.reply(status, message)


def main():
    buffer = EventBuffer()
    credential_path = (
        Path.home()
        / ".config/project10/credentials/telemetry-producers.json"
    )
    configuration = json.loads(
        credential_path.read_text(encoding="utf-8"),
        object_pairs_hook=unique_object,
    )
    authenticator = ProducerAuthenticator(configuration)
    server = CollectorServer(
        ("127.0.0.1", 8100), buffer, authenticator
    )
    worker = DeliveryWorker(buffer, LokiClient())
    worker.start()

    print("Collector listening on http://127.0.0.1:8100")
    print("Delivery: local Loki; failed events remain buffered")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        worker.stop()
        print("Collector stopped; undelivered in-memory events are not persisted")


if __name__ == "__main__":
    main()