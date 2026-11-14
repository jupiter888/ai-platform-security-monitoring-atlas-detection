"""Detector freshness, failure, backlog, and HTTP metric tests."""

import unittest
from urllib.error import HTTPError
from urllib.request import ProxyHandler, build_opener

from src.detection.metrics import MonitorMetrics, start_metrics_server


class DetectorMetricsTests(unittest.TestCase):
    def poll(self, **changes):
        result = {
            "event": "detection_poll",
            "status": "ok",
            "query_status": "ok",
            "delivery_status": "ok",
            "records_scanned": 5,
            "findings_queued": 1,
            "findings_suppressed": 0,
            "delivery_attempted": 1,
            "delivery_failed": 0,
            "findings_delivered": 1,
            "outbox_pending": 0,
            "outbox_delivered": 3,
        }
        result.update(changes)
        return result

    def test_startup_does_not_claim_success(self):
        rendered = MonitorMetrics().render()
        self.assertIn(
            "p10_detector_last_success_timestamp_seconds 0\n",
            rendered,
        )
        self.assertIn("p10_detector_outbox_pending nan\n", rendered)

    def test_failure_preserves_last_success_time(self):
        metrics = MonitorMetrics()
        metrics.observe(self.poll(), now=100)
        metrics.observe(
            self.poll(status="error", query_status="error"),
            now=110,
        )
        rendered = metrics.render()
        self.assertIn("p10_detector_polls_total 2\n", rendered)
        self.assertIn("p10_detector_poll_errors_total 1\n", rendered)
        self.assertIn(
            "p10_detector_last_success_timestamp_seconds 100\n",
            rendered,
        )
        self.assertIn(
            "p10_detector_last_poll_timestamp_seconds 110\n",
            rendered,
        )

    def test_delivery_failure_is_visible_with_pending_backlog(self):
        metrics = MonitorMetrics()
        metrics.observe(self.poll(
            status="error",
            delivery_status="error",
            delivery_failed=1,
            findings_delivered=0,
            outbox_pending=1,
        ))
        rendered = metrics.render()
        self.assertIn("p10_detector_delivery_failures_total 1\n", rendered)
        self.assertIn("p10_detector_outbox_pending 1\n", rendered)
        self.assertIn("p10_detector_query_cycle_healthy 1\n", rendered)
        self.assertIn("p10_detector_delivery_cycle_healthy 0\n", rendered)

    def test_unreadable_backlog_is_not_reported_as_zero(self):
        metrics = MonitorMetrics()
        metrics.observe(self.poll())
        metrics.observe(self.poll(
            status="error",
            outbox_pending=None,
            outbox_delivered=None,
        ))
        self.assertIn(
            "p10_detector_outbox_pending nan\n", metrics.render()
        )

    def test_untrusted_extra_fields_are_not_exported(self):
        metrics = MonitorMetrics()
        metrics.observe(self.poll(
            caller_ref="identity-canary",
            prompt="input-canary",
            credential="credential-canary",
        ))
        rendered = metrics.render()
        for canary in (
            "identity-canary", "input-canary", "credential-canary"
        ):
            self.assertNotIn(canary, rendered)

    def test_http_metrics_endpoint_and_unknown_path(self):
        server = start_metrics_server(MonitorMetrics(), port=0)
        opener = build_opener(ProxyHandler({}))
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with opener.open(base + "/metrics", timeout=3) as response:
                self.assertEqual(response.status, 200)
                self.assertIn(
                    b"p10_detector_polls_total",
                    response.read(),
                )
            with self.assertRaises(HTTPError) as caught:
                opener.open(base + "/unknown", timeout=3)
            self.assertEqual(caught.exception.code, 404)
            caught.exception.close()
        finally:
            server.shutdown()
            server.server_close()

if __name__ == "__main__":
    unittest.main()