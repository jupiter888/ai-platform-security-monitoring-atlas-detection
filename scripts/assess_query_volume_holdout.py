"""
Project 10 — Independent assessment of the frozen held-out run.

Uses actual source events, recorded monitor coverage, durable outbox
records, and receiver records. No traffic or findings are generated.
"""

import hashlib
import json
import sqlite3
from contextlib import closing
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

from src.detection.catalog import QUERY_VOLUME_RULE, SUSTAINED_QUERY_RULE
from src.detection.evaluation import (
    assess_monitor_coverage,
    peak_window_count,
)
from src.detection.model_access import utc_timestamp
from src.detection.store import validate_finding
from src.telemetry.ingestion import parse_event
from src.telemetry.loki import NoRedirects, collection_timestamp_ns


EXPECTED_HASH = (
    "d73eac2f56e2a7161c384d1dec5c5007a22842d87d3a3575d303628a96e5530b"
)
OUTPUT = Path("evidence/public/query-volume-holdout-assessment.json")


def threshold_crossing(timestamps, threshold, window_seconds):
    if (
        type(threshold) is not int or threshold < 1
        or type(window_seconds) is not int or window_seconds < 1
    ):
        raise ValueError("Invalid threshold configuration")

    for timestamp in timestamps:
        utc_timestamp(timestamp.isoformat())

    ordered = sorted(timestamps)
    left = 0

    for right, timestamp in enumerate(ordered):
        while (
            timestamp - ordered[left]
        ).total_seconds() >= window_seconds:
            left += 1

        if right - left + 1 >= threshold:
            return timestamp

    return None


def read_database(path, query):
    with closing(sqlite3.connect(
        path.as_uri() + "?mode=ro",
        uri=True,
    )) as connection:
        return connection.execute(query).fetchall()


def read_polls():
    raw = Path(
        "evidence/public/holdout-monitor.jsonl"
    ).read_bytes()

    if len(raw) > 20_971_520:
        raise RuntimeError("Monitor log exceeds assessment limit")

    polls = []
    lines = raw.decode("utf-8").splitlines()

    for index, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            if index == len(lines) - 1:
                continue
            raise RuntimeError("Malformed monitor log") from None

        if record.get("event") == "detection_poll":
            polls.append(record)

    return polls


def read_events(opener, scenario):
    start = utc_timestamp(scenario["started_at"])
    end = utc_timestamp(scenario["traffic_completed_at"])

    parameters = urlencode({
        "query": (
            '{job="p10-security",source="gateway",provenance="live-lab"}'
            ' | json'
            ' | reason="inference_succeeded"'
            ' | caller_ref="lab-caller-reader"'
            ' | model="research-model"'
        ),
        "start": collection_timestamp_ns(start.isoformat()),
        "end": collection_timestamp_ns(
            (end + timedelta(seconds=1)).isoformat()
        ),
        "direction": "forward",
        "limit": "500",
    })

    with opener.open(
        Request(
            "http://127.0.0.1:3100/loki/api/v1/query_range?"
            + parameters
        ),
        timeout=10,
    ) as response:
        raw = response.read(1_048_577)

    if len(raw) > 1_048_576:
        raise RuntimeError("Event response exceeds assessment limit")

    result = json.loads(raw)
    if result.get("status") != "success":
        raise RuntimeError("Historical event query failed")

    lines = [
        line
        for stream in result["data"]["result"]
        for _, line in stream["values"]
    ]
    if len(lines) >= 500:
        raise RuntimeError("Query limit reached")

    events = {}
    for line in lines:
        payload = json.loads(line)
        collected_at = payload.pop("collected_at")
        event = parse_event(
            json.dumps(payload).encode("utf-8")
        ).event

        if (
            event.source != "gateway"
            or event.provenance != "live-lab"
            or event.reason != "inference_succeeded"
            or event.caller_ref != "lab-caller-reader"
            or event.model != "research-model"
        ):
            raise RuntimeError("Unexpected source event")

        record = {
            "request_id": event.request_id,
            "collected_at": collected_at,
            "event": event.to_json(),
        }
        if event.event_id in events and events[event.event_id] != record:
            raise RuntimeError("Conflicting duplicate source event")
        events[event.event_id] = record

    expected = {
        item["request_id"]
        for item in scenario["observations"]
    }
    if (
        len(events) != len(scenario["observations"])
        or {event["request_id"] for event in events.values()} != expected
    ):
        raise RuntimeError("Scenario source evidence is incomplete or mixed")

    return events


def matching_findings(rows, events):
    matches = []
    for payload_json, timestamp in rows:
        finding = json.loads(payload_json)

        if finding["rule_id"] not in {"DET-002", "DET-003"}:
            continue

        ids = set(finding["event_ids"])
        if not ids.intersection(events):
            continue

        if not ids.issubset(events):
            raise RuntimeError("Finding spans isolated scenarios")

        validate_finding(finding)

        times = [
            utc_timestamp(events[event_id]["collected_at"])
            for event_id in finding["event_ids"]
        ]
        if (
            utc_timestamp(finding["first_seen"]) != min(times)
            or utc_timestamp(finding["last_seen"]) != max(times)
        ):
            raise RuntimeError("Finding timestamps do not match evidence")

        matches.append((finding, timestamp))

    return matches


def summarize(scenarios, mode, outcome):
    counts = {
        "true_positives": 0,
        "false_positives": 0,
        "true_negatives": 0,
        "false_negatives": 0,
    }
    excluded = 0

    for scenario in scenarios:
        if scenario["assessment_status"] != "assessed":
            excluded += 1
            continue

        results = scenario["rules"]
        if mode == "combined":
            positive = any(
                results[rule_id][outcome]
                for rule_id in ("DET-002", "DET-003")
            )
        else:
            positive = results[mode][outcome]

        adversarial = (
            scenario["ground_truth"] == "authorized-adversarial-emulation"
        )

        key = (
            "true_positives" if adversarial and positive
            else "false_negatives" if adversarial
            else "false_positives" if positive
            else "true_negatives"
        )
        counts[key] += 1

    tp = counts["true_positives"]
    fp = counts["false_positives"]
    fn = counts["false_negatives"]

    return {
        **counts,
        "inconclusive_scenarios_excluded": excluded,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
    }


def main():
    if OUTPUT.exists():
        raise RuntimeError("Existing assessment preserved; no overwrite")

    manifest_raw = Path(
        "config/evaluation/query-volume-holdout.json"
    ).read_bytes()
    if hashlib.sha256(manifest_raw).hexdigest() != EXPECTED_HASH:
        raise RuntimeError("Frozen manifest changed")

    manifest = json.loads(manifest_raw)
    run = json.loads(
        Path(
            "evidence/public/query-volume-holdout-run.json"
        ).read_text(encoding="utf-8")
    )

    if (
        run["status"] != "traffic_completed"
        or run["manifest_sha256"] != EXPECTED_HASH
        or run["inference_requests_attempted"] != 124
        or len(run["scenarios"]) != 4
        or asdict(QUERY_VOLUME_RULE) != manifest["baseline_rule"]
        or asdict(SUSTAINED_QUERY_RULE) != manifest["candidate_rule"]
    ):
        raise RuntimeError("Run or rule configuration differs from protocol")

    directory = Path.home() / ".local/share/project10/monitoring"
    queued_rows = read_database(
        directory / "outbox.sqlite3",
        "SELECT payload_json, queued_at FROM finding_outbox",
    )
    received_rows = read_database(
        directory / "findings.sqlite3",
        "SELECT payload_json, received_at FROM findings",
    )
    delivery_history = read_database(
        directory / "outbox.sqlite3",
        "SELECT payload_json, queued_at, delivered_at FROM finding_outbox",
    )

    polls = read_polls()
    opener = build_opener(ProxyHandler({}), NoRedirects())
    assessed = []

    for definition, scenario in zip(
        manifest["scenarios"], run["scenarios"]
    ):
        if (
            scenario["scenario_id"] != definition["scenario_id"]
            or scenario["ground_truth"] != definition["ground_truth"]
            or scenario["status"] != "traffic_completed"
            or [
                item["text"] for item in scenario["observations"]
            ] != definition["queries"]
        ):
            raise RuntimeError("Scenario execution differs from manifest")

        events = read_events(opener, scenario)
        timestamps = [
            utc_timestamp(event["collected_at"])
            for event in events.values()
        ]
        started = utc_timestamp(scenario["started_at"])
        observed_until = utc_timestamp(
            scenario["observation_completed_at"]
        )
        coverage = assess_monitor_coverage(
            polls,
            started_at=started,
            completed_at=observed_until,
        )

        prior_state_clear = True
        for payload_json, queued_at, delivered_at in delivery_history:
            finding = json.loads(payload_json)
            if (
                finding["rule_id"] not in {"DET-002", "DET-003"}
                or finding["caller_ref"] != "lab-caller-reader"
                or finding["model"] != "research-model"
                or utc_timestamp(queued_at) >= started
            ):
                continue

            if delivered_at is None:
                prior_state_clear = False
            else:
                delivered = utc_timestamp(delivered_at)
                if delivered >= started or (
                    started - delivered
                ).total_seconds() < 65:
                    prior_state_clear = False

        queued = matching_findings(queued_rows, events)
        received = matching_findings(received_rows, events)
        rule_results = {}

        for rule in (QUERY_VOLUME_RULE, SUSTAINED_QUERY_RULE):
            queued_in_scope = [
                finding
                for finding, queued_at in queued
                if (
                    finding["rule_id"] == rule.rule_id
                    and started <= utc_timestamp(queued_at) <= observed_until
                )
            ]
            delivered_in_scope = [
                (finding, received_at)
                for finding, received_at in received
                if (
                    finding["rule_id"] == rule.rule_id
                    and started <= utc_timestamp(received_at) <= observed_until
                )
            ]

            crossing = threshold_crossing(
                timestamps,
                rule.threshold,
                rule.window_seconds,
            )

            detected_times = [
                utc_timestamp(finding["detected_at"])
                for finding in queued_in_scope
            ]
            received_times = [
                utc_timestamp(received_at)
                for _, received_at in delivered_in_scope
            ]

            detection_latency = (
                (min(detected_times) - crossing).total_seconds()
                if crossing is not None and detected_times
                else None
            )
            delivery_latency = (
                (min(received_times) - crossing).total_seconds()
                if crossing is not None and received_times
                else None
            )

            if any(
                value is not None and value < 0
                for value in (detection_latency, delivery_latency)
            ):
                raise RuntimeError("Inconsistent latency timestamps")

            rule_results[rule.rule_id] = {
                "peak_window_count": peak_window_count(
                    timestamps, rule.window_seconds
                ),
                "threshold": rule.threshold,
                "window_seconds": rule.window_seconds,
                "condition_met": crossing is not None,
                "finding_queued": bool(queued_in_scope),
                "finding_delivered": bool(delivered_in_scope),
                "finding_ids": [
                    finding["finding_id"] for finding in queued_in_scope
                ],
                "threshold_to_detection_seconds": detection_latency,
                "threshold_to_receiver_storage_seconds": delivery_latency,
            }

        complete = (
            coverage["coverage_complete"] and prior_state_clear
        )
        result = {
            "scenario_id": scenario["scenario_id"],
            "name": scenario["name"],
            "ground_truth": scenario["ground_truth"],
            "events_verified": len(events),
            "assessment_status": "assessed" if complete else "inconclusive",
            "monitor_coverage": coverage,
            "prior_suppression_state_clear": prior_state_clear,
            "rules": rule_results,
            "replica_evaluation": scenario.get("replica_evaluation"),
        }
        assessed.append(result)

        print(
            f"{scenario['scenario_id']}: {len(events)} events verified; "
            f"{result['assessment_status']}"
        )
        for rule_id, values in rule_results.items():
            print(
                f"  {rule_id}: peak={values['peak_window_count']}; "
                f"queued={values['finding_queued']}; "
                f"delivered={values['finding_delivered']}"
            )

    summary = {
        outcome: {
            mode: summarize(assessed, mode, outcome)
            for mode in ("DET-002", "DET-003", "combined")
        }
        for outcome in ("finding_queued", "finding_delivered")
    }

    assessment = {
        "evaluation_type": "frozen-heldout-local-verification",
        "manifest_sha256": EXPECTED_HASH,
        "requests_verified": sum(
            scenario["events_verified"] for scenario in assessed
        ),
        "scenarios": assessed,
        "selected_scenario_results": summary,
        "limitations": [
            "Four deterministic scenarios, not a representative benchmark",
            "New scenario instances use related synthetic vocabulary",
            "Ground truth describes authorized laboratory objectives",
            "Detection and receiver delivery are measured separately",
            "Latency starts when the collection-time threshold is crossed",
            "Recorded monitor coverage cannot prove every internal operation",
            "No production detection-performance claim",
        ],
    }

    OUTPUT.write_text(
        json.dumps(assessment, indent=2) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(summary, indent=2))
    print("Held-out assessment saved; thresholds and manifest unchanged.")

if __name__ == "__main__":
    main()