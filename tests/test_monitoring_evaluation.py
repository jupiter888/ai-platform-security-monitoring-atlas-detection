"""
Window measurement and monitor coverage tests.
"""

import unittest
from datetime import datetime, timedelta, timezone

from src.detection.evaluation import (
    assess_monitor_coverage,
    peak_window_count,
)


NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)


def poll(offset, status="ok"):
    return {
        "timestamp": (NOW + timedelta(seconds=offset)).isoformat(),
        "status": status,
        "query_status": status,
        "delivery_status": status,
        "findings_suppressed": 0,
    }


class MonitoringEvaluationTests(unittest.TestCase):
    def test_empty_window(self):
        self.assertEqual(peak_window_count([]), 0)

    def test_paced_requests_remain_below_twenty(self):
        timestamps = [
            NOW + timedelta(seconds=index * 3.5)
            for index in range(36)
        ]
        self.assertEqual(peak_window_count(timestamps), 18)

    def test_twenty_simultaneous_events_count_as_twenty(self):
        self.assertEqual(peak_window_count([NOW] * 20), 20)

    def test_exact_lower_boundary_is_excluded(self):
        self.assertEqual(
            peak_window_count([NOW, NOW + timedelta(seconds=60)]),
            1,
        )

    def test_input_order_does_not_change_peak(self):
        timestamps = [
            NOW + timedelta(seconds=index * 3.5)
            for index in range(36)
        ]
        self.assertEqual(
            peak_window_count(timestamps),
            peak_window_count(list(reversed(timestamps))),
        )

    def test_naive_timestamp_is_rejected(self):
        with self.assertRaises(ValueError):
            peak_window_count([datetime(2026, 11, 13, 12, 0)])

    def test_healthy_bracketed_coverage(self):
        result = assess_monitor_coverage(
            [poll(offset) for offset in (0, 5, 10, 15)],
            started_at=NOW + timedelta(seconds=1),
            completed_at=NOW + timedelta(seconds=14),
        )
        self.assertTrue(result["coverage_complete"])
        self.assertFalse(result["suppression_observed"])

    def test_error_poll_prevents_healthy_coverage_claim(self):
        result = assess_monitor_coverage(
            [poll(0), poll(5, "error"), poll(10)],
            started_at=NOW + timedelta(seconds=1),
            completed_at=NOW + timedelta(seconds=9),
        )
        self.assertFalse(result["coverage_complete"])

    def test_large_gap_prevents_healthy_coverage_claim(self):
        result = assess_monitor_coverage(
            [poll(0), poll(20)],
            started_at=NOW + timedelta(seconds=1),
            completed_at=NOW + timedelta(seconds=19),
        )
        self.assertFalse(result["coverage_complete"])

    def test_missing_end_poll_prevents_coverage_claim(self):
        result = assess_monitor_coverage(
            [poll(0), poll(5)],
            started_at=NOW + timedelta(seconds=1),
            completed_at=NOW + timedelta(seconds=10),
        )
        self.assertFalse(result["coverage_complete"])

if __name__ == "__main__":
    unittest.main()