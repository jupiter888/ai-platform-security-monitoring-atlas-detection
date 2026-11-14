"""
Project 10 — Retrospective query-window comparison.

Uses original event records from completed development scenarios.
Does not modify rules, submit traffic, or create findings.
"""

import json
import re
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

from src.detection.evaluation import peak_window_count
from src.detection.model_access import utc_timestamp
from src.detection.store import validate_finding
from src.telemetry.ingestion import CollectedEvent, parse_event
from src.telemetry.loki import NoRedirects, collection_timestamp_ns


BASELINE_THRESHOLD = 20
BASELINE_WINDOW = 60
CANDIDATE_THRESHOLD = 30
CANDIDATE_WINDOW = 180

SELECTOR = (
    '{job="p10-security",source="gateway",provenance="live-lab"}'
    ' | json'
    ' | reason="inference_succeeded"'
    ' | caller_ref="lab-caller-reader"'
    ' | model="research-model"'
)


def get_json(opener, request):
    with opener.open(request, timeout=10) as response:
        raw = response.read(1_048_577)

        if response.status != 200 or len(raw) > 1_048_576:
            raise RuntimeError("Unexpected comparison response")

        return json.loads(raw)


def query_events(opener, start_ns, end_ns):
    parameters = urlencode({
        "query": SELECTOR,
        "start": str(start_ns),
        "end": str(end_ns),
        "direction": "forward",
        "limit": "500",
    })
    result = get_json(
        opener,
        Request(
            "http://127.0.0.1:3100/loki/api/v1/query_range?"
            + parameters
        ),
    )
    if result.get("status") != "success":
        raise RuntimeError("Historical event query failed")

    lines = [
        line
        for stream in result["data"]["result"]
        for _, line in stream["values"]
    ]
    if len(lines) >= 500:
        raise RuntimeError("Query limit reached")

    distinct = {}

    for line in lines:
        payload = json.loads(line)
        collected_at = payload.pop("collected_at")
        validated = parse_event(json.dumps(payload).encode("utf-8"))
        record = CollectedEvent(
            event=validated.event,
            collected_at=collected_at,
        )

        if (
            record.event.source != "gateway"
            or record.event.provenance != "live-lab"
            or record.event.reason != "inference_succeeded"
            or record.event.caller_ref != "lab-caller-reader"
            or record.event.model != "research-model"
        ):
            raise RuntimeError("Unexpected historical event")

        event_id = record.event.event_id
        if (
            event_id in distinct
            and distinct[event_id].to_json() != record.to_json()
        ):
            raise RuntimeError("Conflicting duplicate event")

        distinct[event_id] = record

    return list(distinct.values())


def experiment_events(opener, path):
    report = json.loads(path.read_text(encoding="utf-8"))
    observations = (
        report["training_observations"]
        + report["heldout_observations"]
    )
    expected_requests = {
        item["request_id"] for item in observations
    }

    if len(expected_requests) != 36:
        raise RuntimeError("Unexpected experiment request count")

    started = utc_timestamp(report["started_at"])
    completed = utc_timestamp(report["completed_at"])

    records = query_events(
        opener,
        collection_timestamp_ns(started.isoformat()),
        collection_timestamp_ns(
            (completed + timedelta(seconds=1)).isoformat()
        ),
    )

    if (
        len(records) != 36
        or {record.event.request_id for record in records}
        != expected_requests
    ):
        raise RuntimeError("Experiment telemetry is incomplete or mixed")

    return records


def summarize(rows, decision):
    counts = {
        "true_positives": 0,
        "false_positives": 0,
        "true_negatives": 0,
        "false_negatives": 0,
    }

    for row in rows:
        fired = row[decision]
        adversarial = row["ground_truth"] == "adversarial-emulation"

        if adversarial and fired:
            counts["true_positives"] += 1
        elif adversarial:
            counts["false_negatives"] += 1
        elif fired:
            counts["false_positives"] += 1
        else:
            counts["true_negatives"] += 1

    tp = counts["true_positives"]
    fp = counts["false_positives"]
    fn = counts["false_negatives"]

    return {
        **counts,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
    }


def main():
    opener = build_opener(ProxyHandler({}), NoRedirects())

    previous = json.loads(
        Path(
            "evidence/public/query-volume-scenario-comparison.json"
        ).read_text(encoding="utf-8")
    )
    benign_summary = next(
        scenario
        for scenario in previous["scenarios"]
        if scenario["name"] == "approved-research-batch"
    )
    finding_id = benign_summary["finding_id"]

    if re.fullmatch(r"[0-9a-f]{64}", finding_id) is None:
        raise RuntimeError("Invalid benign finding identifier")

    key = (
        Path.home()
        / ".config/project10/credentials/finding-receiver-key"
    ).read_text(encoding="utf-8")

    stored = get_json(
        opener,
        Request(
            "http://127.0.0.1:8300/findings/" + finding_id,
            headers={"Authorization": f"Bearer {key}"},
        ),
    )
    benign_finding = stored["finding"]
    validate_finding(benign_finding)

    if (
        benign_finding["finding_id"] != finding_id
        or benign_finding["rule_id"] != "DET-002"
        or benign_finding["event_count"] != 20
    ):
        raise RuntimeError("Unexpected approved-batch evidence")

    benign_records = query_events(
        opener,
        collection_timestamp_ns(benign_finding["first_seen"]),
        int(collection_timestamp_ns(benign_finding["last_seen"])) + 1,
    )

    if {record.event.event_id for record in benign_records} != set(
        benign_finding["event_ids"]
    ):
        raise RuntimeError("Approved-batch telemetry is incomplete or mixed")

    burst_records = experiment_events(
        opener,
        Path("evidence/public/model-replication-experiment.json"),
    )
    paced_records = experiment_events(
        opener,
        Path("evidence/public/paced-replication-experiment.json"),
    )

    scenarios = [
        ("approved-research-batch", "benign", benign_records),
        (
            "burst-model-replication",
            "adversarial-emulation",
            burst_records,
        ),
        (
            "paced-model-replication",
            "adversarial-emulation",
            paced_records,
        ),
    ]

    rows = []
    for name, ground_truth, records in scenarios:
        timestamps = [
            utc_timestamp(record.collected_at)
            for record in records
        ]
        peak_60 = peak_window_count(
            timestamps, BASELINE_WINDOW
        )
        peak_180 = peak_window_count(
            timestamps, CANDIDATE_WINDOW
        )

        baseline = peak_60 >= BASELINE_THRESHOLD
        candidate = peak_180 >= CANDIDATE_THRESHOLD

        rows.append({
            "scenario": name,
            "ground_truth": ground_truth,
            "events_verified": len(records),
            "peak_requests_60_seconds": peak_60,
            "peak_requests_180_seconds": peak_180,
            "baseline_condition_met": baseline,
            "candidate_condition_met": candidate,
            "combined_condition_met": baseline or candidate,
        })

    # Preserve consistency with the observed development baseline.
    if [
        row["baseline_condition_met"] for row in rows
    ] != [True, True, False]:
        raise RuntimeError("Historical baseline differs from recorded outcomes")

    report = {
        "analysis_type": "retrospective-development-comparison",
        "live_configuration_changed": False,
        "alerts_generated_by_this_script": False,
        "baseline": {
            "threshold": BASELINE_THRESHOLD,
            "window_seconds": BASELINE_WINDOW,
        },
        "candidate": {
            "threshold": CANDIDATE_THRESHOLD,
            "window_seconds": CANDIDATE_WINDOW,
        },
        "scenarios": rows,
        "selected_scenario_results": {
            "baseline": summarize(rows, "baseline_condition_met"),
            "candidate_alone": summarize(rows, "candidate_condition_met"),
            "combined": summarize(rows, "combined_condition_met"),
        },
        "limitations": [
            "Candidate selected after inspecting these development scenarios",
            "Retrospective condition matching is not a historical live alert",
            "Each scenario is evaluated in isolation",
            "No representative or population-level performance claim",
            "Held-out validation is still required",
            "Longer windows do not establish intent",
        ],
    }

    Path(
        "evidence/public/development-window-comparison.json"
    ).write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(report, indent=2))
    print("Retrospective comparison completed; live rules unchanged.")

if __name__ == "__main__":
    main()