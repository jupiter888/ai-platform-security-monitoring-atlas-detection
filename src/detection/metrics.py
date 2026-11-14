"""Bounded, process-local monitoring metrics for the detection worker."""

import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


class MonitorMetrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.values = {
            "polls_total": 0,
            "poll_errors_total": 0,
            "findings_queued_total": 0,
            "findings_suppressed_total": 0,
            "delivery_attempts_total": 0,
            "delivery_failures_total": 0,
            "findings_delivered_total": 0,
            "last_poll_timestamp_seconds": 0,
            "last_success_timestamp_seconds": 0,
            "query_cycle_healthy": 0,
            "delivery_cycle_healthy": 0,
            "last_poll_records_scanned": 0,
            "outbox_pending": float("nan"),
            "outbox_delivered": float("nan"),
        }

    def observe(self, poll, *, now=None):
        timestamp = time.time() if now is None else now
        with self.lock:
            values = self.values
            values["polls_total"] += 1
            healthy = poll.get("status") == "ok"
            values["poll_errors_total"] += int(not healthy)
            values["last_poll_timestamp_seconds"] = timestamp
            if healthy:
                values["last_success_timestamp_seconds"] = timestamp

            values["query_cycle_healthy"] = int(
                poll.get("query_status") == "ok"
            )
            values["delivery_cycle_healthy"] = int(
                poll.get("delivery_status") == "ok"
            )

            counters = {
                "findings_queued": "findings_queued_total",
                "findings_suppressed": "findings_suppressed_total",
                "delivery_attempted": "delivery_attempts_total",
                "delivery_failed": "delivery_failures_total",
                "findings_delivered": "findings_delivered_total",
            }
            for source, target in counters.items():
                value = poll.get(source, 0)
                if type(value) is int and value >= 0:
                    values[target] += value

            scanned = poll.get("records_scanned")
            values["last_poll_records_scanned"] = (
                scanned
                if type(scanned) is int and scanned >= 0
                else float("nan")
            )

            for name in ("outbox_pending", "outbox_delivered"):
                value = poll.get(name)
                values[name] = (
                    value
                    if type(value) is int and value >= 0
                    else float("nan")
                )

    def render(self):
        with self.lock:
            snapshot = dict(self.values)

        lines = []
        for suffix, value in snapshot.items():
            name = "p10_detector_" + suffix
            kind = "counter" if suffix.endswith("_total") else "gauge"
            lines.append(f"# TYPE {name} {kind}")
            lines.append(f"{name} {value}")
        return "\n".join(lines) + "\n"


def start_metrics_server(metrics, *, port=8500):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(2)

        def do_GET(self):
            if self.path != "/metrics":
                self.send_error(404)
                return

            payload = metrics.render().encode("utf-8")
            self.send_response(200)
            self.send_header(
                "Content-Type", "text/plain; version=0.0.4"
            )
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, _format, *args):
            pass

    server = HTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(
        target=server.serve_forever,
        name="detector-metrics",
        daemon=True,
    )
    thread.start()
    return server