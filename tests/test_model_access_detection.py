"""
DET-001 threshold, grouping, window, and duplicate tests.
"""

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from src.detection.model_access import detect_model_access
from src.telemetry.events import create_event
from src.telemetry.ingestion import CollectedEvent


NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)


def make_record(
    *,
    age=1,
    caller="lab-caller-reader",
    model="restricted-model",
    source="gateway",
    provenance="live-lab",
    reason="model_access_denied",
):
    event = create_event(
        provenance=provenance,
        source=source,
        model=model,
        reason=reason,
        caller_ref=caller,
    )
    return CollectedEvent(
        event=event,
        collected_at=(NOW - timedelta(seconds=age)).isoformat(),
    )


class ModelAccessDetectionTests(unittest.TestCase):
    def evaluate(self, records):
        return detect_model_access(records, as_of=NOW)

    def test_below_threshold_produces_no_finding(self):
        records = [make_record() for _ in range(4)]
        self.assertEqual(self.evaluate(records), [])

    def test_threshold_produces_one_finding(self):
        records = [make_record(age=age) for age in range(1, 6)]
        findings = self.evaluate(records)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "DET-001")
        self.assertEqual(findings[0]["event_count"], 5)
        self.assertEqual(len(findings[0]["event_ids"]), 5)

    def test_duplicate_entries_do_not_inflate_count(self):
        records = [make_record() for _ in range(4)]
        records.extend([records[0], records[0]])
        self.assertEqual(self.evaluate(records), [])

    def test_conflicting_duplicate_is_rejected(self):
        first = make_record()
        conflicting = replace(
            first,
            event=replace(
                first.event,
                caller_ref="lab-caller-other",
            ),
        )
        with self.assertRaises(ValueError):
            self.evaluate([first, conflicting])

    def test_lower_window_boundary_is_excluded(self):
        records = [make_record() for _ in range(4)]
        records.append(make_record(age=60))
        records.append(make_record(age=61))
        self.assertEqual(self.evaluate(records), [])

    def test_future_collection_time_is_excluded(self):
        records = [make_record() for _ in range(4)]
        records.append(make_record(age=-1))
        self.assertEqual(self.evaluate(records), [])

    def test_caller_and_model_groups_do_not_mix(self):
        records = [make_record() for _ in range(4)]
        records.append(make_record(caller="lab-caller-other"))
        records.append(make_record(model="research-model"))
        self.assertEqual(self.evaluate(records), [])

    def test_successful_inference_is_not_a_denial(self):
        records = [
            make_record(reason="inference_succeeded")
            for _ in range(8)
        ]
        self.assertEqual(self.evaluate(records), [])

    def test_other_sources_and_provenance_are_excluded(self):
        for overrides in (
            {"source": "backend"},
            {"provenance": "synthetic"},
            {"provenance": "replay"},
        ):
            with self.subTest(overrides=overrides):
                records = [
                    make_record(**overrides)
                    for _ in range(5)
                ]
                self.assertEqual(self.evaluate(records), [])

    def test_input_order_does_not_change_finding_identity(self):
        records = [make_record(age=age) for age in range(1, 6)]
        forward = self.evaluate(records)
        backward = self.evaluate(list(reversed(records)))

        self.assertEqual(forward, backward)

if __name__ == "__main__":
    unittest.main()