"""
DET-002 threshold, grouping, provenance, and counting tests.
"""

import unittest
from datetime import datetime, timedelta, timezone

from src.detection.model_access import (
    detect_model_access,
    detect_query_volume,
)
from src.telemetry.events import create_event
from src.telemetry.ingestion import CollectedEvent


NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)


def make_record(
    *,
    age=1,
    caller="lab-caller-reader",
    model="research-model",
    reason="inference_succeeded",
    provenance="live-lab",
):
    return CollectedEvent(
        event=create_event(
            provenance=provenance,
            source="gateway",
            model=model,
            reason=reason,
            caller_ref=caller,
        ),
        collected_at=(NOW - timedelta(seconds=age)).isoformat(),
    )


class QueryVolumeDetectionTests(unittest.TestCase):
    def evaluate(self, records):
        return detect_query_volume(records, as_of=NOW)

    def test_nineteen_requests_do_not_trigger(self):
        records = [make_record() for _ in range(19)]
        self.assertEqual(self.evaluate(records), [])

    def test_twenty_requests_trigger(self):
        records = [make_record() for _ in range(20)]
        findings = self.evaluate(records)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "DET-002")
        self.assertEqual(findings[0]["event_count"], 20)

    def test_duplicate_entries_do_not_inflate_volume(self):
        records = [make_record() for _ in range(19)]
        records.extend([records[0], records[0]])
        self.assertEqual(self.evaluate(records), [])

    def test_denied_requests_do_not_count_as_successful_inference(self):
        records = [
            make_record(reason="model_access_denied")
            for _ in range(20)
        ]
        self.assertEqual(self.evaluate(records), [])

    def test_callers_and_models_are_separate(self):
        records = [make_record() for _ in range(19)]
        records.append(make_record(caller="lab-caller-other"))
        records.append(make_record(model="restricted-model"))

        self.assertEqual(self.evaluate(records), [])

    def test_expired_and_future_events_do_not_count(self):
        records = [make_record() for _ in range(19)]
        records.append(make_record(age=60))
        records.append(make_record(age=-1))

        self.assertEqual(self.evaluate(records), [])

    def test_synthetic_and_replay_events_are_excluded(self):
        for provenance in ("synthetic", "replay"):
            with self.subTest(provenance=provenance):
                records = [
                    make_record(provenance=provenance)
                    for _ in range(20)
                ]
                self.assertEqual(self.evaluate(records), [])

    def test_rule_identity_is_distinct_from_access_denials(self):
        records = [make_record() for _ in range(20)]
        finding = self.evaluate(records)[0]

        self.assertEqual(
            finding["classification"],
            "elevated_inference_query_volume",
        )
        self.assertEqual(finding["threshold"], 20)
        self.assertEqual(
            detect_model_access(records, as_of=NOW),
            [],
        )

if __name__ == "__main__":
    unittest.main()