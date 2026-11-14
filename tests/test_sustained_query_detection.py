"""
DET-003 behavior, pipeline compatibility, & protocol consistency.
"""

import hashlib
import json
import tempfile
import unittest
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from src.detection.catalog import QUERY_VOLUME_RULE, SUSTAINED_QUERY_RULE
from src.detection.model_access import (
    detect_query_volume,
    detect_sustained_query_volume,
)
from src.detection.monitor import LOOKBACK_SECONDS, evaluate_rules
from src.detection.outbox import FindingOutbox
from src.detection.receiver import create_app
from src.detection.store import FindingStore, validate_finding
from src.telemetry.events import create_event
from src.telemetry.ingestion import CollectedEvent


NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)


def records(count, spacing=1, reason="inference_succeeded"):
    return [
        CollectedEvent(
            event=create_event(
                provenance="live-lab",
                source="gateway",
                model="research-model",
                reason=reason,
                caller_ref="lab-caller-reader",
            ),
            collected_at=(
                NOW - timedelta(seconds=1 + index * spacing)
            ).isoformat(),
        )
        for index in range(count)
    ]


class SustainedQueryTests(unittest.TestCase):
    def test_below_threshold_produces_no_finding(self):
        self.assertEqual(
            detect_sustained_query_volume(records(29), as_of=NOW),
            [],
        )

    def test_thirty_paced_events_match_only_longer_window(self):
        events = records(30, spacing=3.5)

        self.assertEqual(detect_query_volume(events, as_of=NOW), [])
        findings = detect_sustained_query_volume(events, as_of=NOW)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "DET-003")
        self.assertEqual(findings[0]["event_count"], 30)

    def test_exact_lower_boundary_is_excluded(self):
        events = records(29)
        boundary = CollectedEvent(
            event=records(1)[0].event,
            collected_at=(NOW - timedelta(seconds=180)).isoformat(),
        )

        self.assertEqual(
            detect_sustained_query_volume(
                events + [boundary], as_of=NOW
            ),
            [],
        )

    def test_duplicates_do_not_inflate_count(self):
        events = records(29)
        self.assertEqual(
            detect_sustained_query_volume(
                events + [events[0]], as_of=NOW
            ),
            [],
        )

    def test_denials_do_not_count_as_successes(self):
        self.assertEqual(
            detect_sustained_query_volume(
                records(30, reason="model_access_denied"),
                as_of=NOW,
            ),
            [],
        )

    def test_receiver_accepts_sustained_finding(self):
        finding = detect_sustained_query_volume(
            records(30), as_of=NOW
        )[0]

        with tempfile.TemporaryDirectory() as directory:
            store = FindingStore(Path(directory) / "findings.sqlite3")
            with TestClient(create_app(
                store=store,
                service_key="a" * 64,
            )) as client:
                response = client.post(
                    "/findings",
                    json=finding,
                    headers={"Authorization": f'Bearer {"a" * 64}'},
                )

            self.assertEqual(response.status_code, 201)
            self.assertEqual(store.count(), 1)

    def test_query_rules_can_queue_for_same_caller_and_model(self):
        findings = evaluate_rules(records(36), as_of=NOW)

        with tempfile.TemporaryDirectory() as directory:
            outbox = FindingOutbox(Path(directory) / "outbox.sqlite3")
            for finding in findings:
                self.assertEqual(
                    outbox.enqueue(finding, as_of=NOW),
                    "queued",
                )

            self.assertEqual(outbox.stats()["pending"], 2)

    def test_rules_match_the_frozen_protocol(self):
        path = Path("config/evaluation/query-volume-holdout.json")
        raw = path.read_bytes()

        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            "d73eac2f56e2a7161c384d1dec5c5007a22842d87d3a3575d303628a96e5530b",
        )
        manifest = json.loads(raw)
        self.assertEqual(
            asdict(QUERY_VOLUME_RULE),
            manifest["baseline_rule"],
        )
        self.assertEqual(
            asdict(SUSTAINED_QUERY_RULE),
            manifest["candidate_rule"],
        )

    def test_monitor_evaluates_three_rules_with_longest_lookback(self):
        findings = evaluate_rules(
            records(36) + records(5, reason="model_access_denied"),
            as_of=NOW,
        )
        self.assertEqual(
            {finding["rule_id"] for finding in findings},
            {"DET-001", "DET-002", "DET-003"},
        )
        self.assertEqual(LOOKBACK_SECONDS, 180)

    def test_incorrect_candidate_threshold_is_rejected(self):
        finding = detect_sustained_query_volume(
            records(30), as_of=NOW
        )[0]
        finding["threshold"] = 20

        with self.assertRaises(ValueError):
            validate_finding(finding)

if __name__ == "__main__":
    unittest.main()