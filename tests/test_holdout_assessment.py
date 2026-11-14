"""
Threshold-crossing time tests for held-out latency measurement.
"""

import unittest
from datetime import datetime, timedelta, timezone

from scripts.assess_query_volume_holdout import threshold_crossing


NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)


class HoldoutAssessmentTests(unittest.TestCase):
    def test_burst_crossing_occurs_on_twentieth_event(self):
        timestamps = [
            NOW + timedelta(seconds=index)
            for index in range(36)
        ]
        self.assertEqual(
            threshold_crossing(timestamps, 20, 60),
            NOW + timedelta(seconds=19),
        )

    def test_paced_queries_do_not_cross_short_window(self):
        timestamps = [
            NOW + timedelta(seconds=index * 3.5)
            for index in range(36)
        ]
        self.assertIsNone(
            threshold_crossing(timestamps, 20, 60)
        )

    def test_paced_queries_cross_long_window(self):
        timestamps = [
            NOW + timedelta(seconds=index * 3.5)
            for index in range(36)
        ]
        self.assertEqual(
            threshold_crossing(timestamps, 30, 180),
            NOW + timedelta(seconds=101.5),
        )

    def test_exact_lower_boundary_does_not_count(self):
        self.assertIsNone(
            threshold_crossing(
                [NOW, NOW + timedelta(seconds=60)],
                2,
                60,
            )
        )

if __name__ == "__main__":
    unittest.main()