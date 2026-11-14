"""
Finding suppression and output-acceptance tests.
"""

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from src.detection.suppression import FindingSuppression


NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)


def finding(caller="lab-caller-reader", fingerprint="first"):
    return {
        "finding_id": fingerprint,
        "rule_id": "DET-001",
        "rule_version": "1.0",
        "caller_ref": caller,
        "model": "restricted-model",
    }


class FindingSuppressionTests(unittest.TestCase):
    def test_first_finding_is_emitted(self):
        state = FindingSuppression()
        sink = Mock(return_value=True)

        self.assertEqual(
            state.publish([finding()], as_of=NOW, sink=sink),
            (1, 0),
        )
        sink.assert_called_once()

    def test_repeat_is_suppressed(self):
        state = FindingSuppression()
        sink = Mock(return_value=True)
        state.publish([finding()], as_of=NOW, sink=sink)

        self.assertEqual(
            state.publish(
                [finding()],
                as_of=NOW + timedelta(seconds=5),
                sink=sink,
            ),
            (0, 1),
        )
        self.assertEqual(sink.call_count, 1)

    def test_changed_fingerprint_does_not_bypass_suppression(self):
        state = FindingSuppression()
        sink = Mock(return_value=True)
        state.publish([finding()], as_of=NOW, sink=sink)

        self.assertEqual(
            state.publish(
                [finding(fingerprint="more-events")],
                as_of=NOW + timedelta(seconds=5),
                sink=sink,
            ),
            (0, 1),
        )

    def test_finding_can_emit_at_cooldown_boundary(self):
        state = FindingSuppression()
        sink = Mock(return_value=True)
        state.publish([finding()], as_of=NOW, sink=sink)

        self.assertEqual(
            state.publish(
                [finding()],
                as_of=NOW + timedelta(seconds=60),
                sink=sink,
            ),
            (1, 0),
        )

    def test_distinct_callers_are_independent(self):
        state = FindingSuppression()
        sink = Mock(return_value=True)

        self.assertEqual(
            state.publish(
                [finding(), finding(caller="lab-caller-other")],
                as_of=NOW,
                sink=sink,
            ),
            (2, 0),
        )

    def test_capacity_does_not_evict_active_suppression(self):
        state = FindingSuppression(capacity=1)
        sink = Mock(return_value=True)
        state.publish([finding()], as_of=NOW, sink=sink)

        with self.assertRaises(RuntimeError):
            state.publish(
                [finding(caller="lab-caller-other")],
                as_of=NOW + timedelta(seconds=1),
                sink=sink,
            )

        self.assertEqual(len(state.entries), 1)
        self.assertEqual(sink.call_count, 1)

    def test_expired_entries_release_capacity(self):
        state = FindingSuppression(capacity=1)
        sink = Mock(return_value=True)
        state.publish([finding()], as_of=NOW, sink=sink)

        self.assertEqual(
            state.publish(
                [finding(caller="lab-caller-other")],
                as_of=NOW + timedelta(seconds=61),
                sink=sink,
            ),
            (1, 0),
        )
        self.assertEqual(len(state.entries), 1)

    def test_failed_sink_does_not_suppress_retry(self):
        state = FindingSuppression()
        sink = Mock(side_effect=[False, True])

        with self.assertRaises(RuntimeError):
            state.publish([finding()], as_of=NOW, sink=sink)

        self.assertEqual(len(state.entries), 0)
        self.assertEqual(
            state.publish([finding()], as_of=NOW, sink=sink),
            (1, 0),
        )

if __name__ == "__main__":
    unittest.main()