"""
Catalog validation and multi-rule pipeline compatibility tests.
"""

import copy
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from src.detection.model_access import detect_query_volume
from src.detection.monitor import evaluate_rules
from src.detection.outbox import FindingOutbox
from src.detection.receiver import create_app
from src.detection.store import FindingStore, validate_finding
from src.telemetry.events import create_event
from src.telemetry.ingestion import CollectedEvent


NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)
SERVICE_KEY = "a" * 64


def records(reason, model, count):
    return [
        CollectedEvent(
            event=create_event(
                provenance="live-lab",
                source="gateway",
                model=model,
                reason=reason,
                caller_ref="lab-caller-reader",
            ),
            collected_at=(NOW - timedelta(seconds=1)).isoformat(),
        )
        for _ in range(count)
    ]


class MultiRuleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = FindingStore(
            Path(self.directory.name) / "findings.sqlite3"
        )
        self.successes = records(
            "inference_succeeded", "research-model", 20
        )
        self.denials = records(
            "model_access_denied", "restricted-model", 5
        )
        self.finding = detect_query_volume(
            self.successes, as_of=NOW
        )[0]

    def tearDown(self):
        self.directory.cleanup()

    def test_store_accepts_det002(self):
        self.assertTrue(self.store.put(self.finding))
        self.assertEqual(
            self.store.get(self.finding["finding_id"])["finding"],
            self.finding,
        )

    def test_receiver_accepts_det002(self):
        with TestClient(create_app(
            store=self.store,
            service_key=SERVICE_KEY,
        )) as client:
            response = client.post(
                "/findings",
                json=self.finding,
                headers={"Authorization": f"Bearer {SERVICE_KEY}"},
            )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            response.json()["finding_id"],
            self.finding["finding_id"],
        )

    def test_receiver_deduplicates_det002(self):
        with TestClient(create_app(
            store=self.store,
            service_key=SERVICE_KEY,
        )) as client:
            headers = {"Authorization": f"Bearer {SERVICE_KEY}"}
            client.post("/findings", json=self.finding, headers=headers)
            response = client.post(
                "/findings", json=self.finding, headers=headers
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["duplicate"])
        self.assertEqual(self.store.count(), 1)

    def test_outbox_accepts_both_rules(self):
        outbox = FindingOutbox(
            Path(self.directory.name) / "outbox.sqlite3"
        )
        findings = evaluate_rules(
            self.successes + self.denials,
            as_of=NOW,
        )
        for finding in findings:
            self.assertEqual(
                outbox.enqueue(finding, as_of=NOW),
                "queued",
            )

        self.assertEqual(outbox.stats()["pending"], 2)

    def test_monitor_evaluates_both_rules(self):
        findings = evaluate_rules(
            self.successes + self.denials,
            as_of=NOW,
        )

        self.assertEqual(
            {finding["rule_id"] for finding in findings},
            {"DET-001", "DET-002"},
        )
        self.assertEqual(
            len({finding["finding_id"] for finding in findings}),
            2,
        )

    def test_wrong_rule_threshold_is_rejected(self):
        changed = copy.deepcopy(self.finding)
        changed["threshold"] = 5

        with self.assertRaises(ValueError):
            validate_finding(changed)

    def test_mismatched_rule_metadata_is_rejected(self):
        for field, value in (
            ("classification", "repeated_model_access_denials"),
            ("severity", "critical"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.finding)
                changed[field] = value
                with self.assertRaises(ValueError):
                    validate_finding(changed)

    def test_unsupported_rule_version_is_rejected(self):
        changed = copy.deepcopy(self.finding)
        changed["rule_version"] = "999"

        with self.assertRaises(ValueError):
            validate_finding(changed)

    def test_unknown_rule_is_rejected(self):
        changed = copy.deepcopy(self.finding)
        changed["rule_id"] = "DET-UNKNOWN"

        with self.assertRaises(ValueError):
            validate_finding(changed)

    def test_evidence_count_mismatch_is_rejected(self):
        changed = copy.deepcopy(self.finding)
        changed["event_count"] = 19

        with self.assertRaises(ValueError):
            validate_finding(changed)

if __name__ == "__main__":
    unittest.main()