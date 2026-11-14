"""
Project 10 — Correlate model-replication activity with stored findings.

Trusted evaluator reads:
- Experiment ground truth from the saved report.
- Actual event records from Loki.
- Candidate finding IDs from the private receiver database.
- Finding contents through the authenticated receiver API.

Ground truth is not supplied to the detection engine.
"""

import json
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener
from uuid import UUID

from src.detection.store import validate_finding
from src.telemetry.loki import NoRedirects, collection_timestamp_ns


def get_json(opener, request):
    with opener.open(request, timeout=10) as response:
        raw = response.read(1_048_577)
        if response.status != 200 or len(raw) > 1_048_576:
            raise RuntimeError("Unexpected assessment response")
        return json.loads(raw)


def retrieve_finding(opener, finding_id, key):
    result = get_json(
        opener,
        Request(
            "http://127.0.0.1:8300/findings/" + finding_id,
            headers={"Authorization": f"Bearer {key}"},
        ),
    )
    validate_finding(result["finding"])
    if result["finding"]["finding_id"] != finding_id:
        raise RuntimeError("Finding retrieval identifier mismatch")
    return result


def main():
    report = json.loads(
        Path(
            "evidence/public/model-replication-experiment.json"
        ).read_text(encoding="utf-8")
    )

    if report["scenario"] != "controlled-output-based-model-replication":
        raise RuntimeError("Unexpected experiment report")

    observations = (
        report["training_observations"]
        + report["heldout_observations"]
    )
    request_ids = {item["request_id"] for item in observations}

    if len(request_ids) != 36 or report["requests_completed"] != 36:
        raise RuntimeError("Unexpected experiment request count")

    for request_id in request_ids:
        parsed = UUID(request_id)
        if parsed.version != 4 or str(parsed) != request_id:
            raise RuntimeError("Invalid experiment correlation identifier")

    opener = build_opener(ProxyHandler({}), NoRedirects())
    started = datetime.fromisoformat(report["started_at"])
    ended = datetime.fromisoformat(report["completed_at"])

    parameters = urlencode({
        "query": (
            '{job="p10-security",source="gateway",provenance="live-lab"}'
            ' | json'
            ' | reason="inference_succeeded"'
            ' | caller_ref="lab-caller-reader"'
            ' | model="research-model"'
        ),
        "start": collection_timestamp_ns(started.isoformat()),
        "end": collection_timestamp_ns(
            (ended + timedelta(seconds=1)).isoformat()
        ),
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
        raise RuntimeError("Experiment event query failed")

    records = [
        json.loads(line)
        for stream in result["data"]["result"]
        for _, line in stream["values"]
    ]
    if len(records) >= 500:
        raise RuntimeError("Query limit reached")

    observed_requests = {record["request_id"] for record in records}
    if observed_requests != request_ids:
        raise RuntimeError(
            "Experiment event coverage is incomplete or mixed "
            "with unrelated requests"
        )

    experiment_event_ids = {record["event_id"] for record in records}
    if len(experiment_event_ids) != 36:
        raise RuntimeError("Unexpected distinct experiment event count")

    print("PASS: all 36 actual inference requests correlate to Loki events")

    database = (
        Path.home()
        / ".local/share/project10/monitoring/findings.sqlite3"
    )
    candidates = []
    deadline = time.monotonic() + 15

    while time.monotonic() < deadline:
        with closing(sqlite3.connect(
            database.as_uri() + "?mode=ro",
            uri=True,
        )) as connection:
            rows = connection.execute(
                "SELECT payload_json FROM findings"
            ).fetchall()

        candidates = []
        for row in rows:
            finding = json.loads(row[0])
            if (
                finding["rule_id"] == "DET-002"
                and finding["caller_ref"] == "lab-caller-reader"
                and finding["model"] == "research-model"
                and len(finding["event_ids"]) >= 20
                and set(finding["event_ids"]).issubset(
                    experiment_event_ids
                )
            ):
                validate_finding(finding)
                candidates.append(finding)

        if candidates:
            break
        time.sleep(1)

    if not candidates:
        raise RuntimeError(
            "No delivered DET-002 finding matches this experiment. "
            "Inspect Tab D and the outbox before repeating any traffic."
        )

    key = (
        Path.home()
        / ".config/project10/credentials/finding-receiver-key"
    ).read_text(encoding="utf-8")

    matched = candidates[0]
    stored = retrieve_finding(opener, matched["finding_id"], key)
    if stored["finding"] != matched:
        raise RuntimeError("Stored finding retrieval mismatch")

    print("PASS: delivered DET-002 evidence belongs to the replication run")

    benign_text = Path(
        "evidence/public/query-volume-benign-batch.txt"
    ).read_text(encoding="utf-8")
    start = benign_text.find("{")
    if start < 0:
        raise RuntimeError("Benign scenario summary not found")

    benign, _ = json.JSONDecoder().raw_decode(benign_text[start:])
    if (
        benign["scenario"] != "approved-research-batch"
        or benign["ground_truth"] != "benign"
    ):
        raise RuntimeError("Unexpected benign scenario ground truth")

    benign_record = retrieve_finding(
        opener,
        benign["finding_id"],
        key,
    )
    if benign_record["finding"]["rule_id"] != "DET-002":
        raise RuntimeError("Benign finding rule mismatch")

    print("PASS: approved batch also has a stored DET-002 finding")

    assessment = {
        "rule_id": "DET-002",
        "evaluation_unit": "selected controlled scenario",
        "scenario_count": 2,
        "scenarios": [
            {
                "name": "approved-research-batch",
                "ground_truth": "benign",
                "finding_delivered": True,
                "classification": "operational_false_positive",
                "finding_id": benign["finding_id"],
            },
            {
                "name": "controlled-output-based-model-replication",
                "ground_truth": "authorized-adversarial-emulation",
                "finding_delivered": True,
                "classification": "true_positive_for_declared_scenario",
                "finding_id": matched["finding_id"],
                "supporting_event_count": matched["event_count"],
            },
        ],
        "selected_scenario_counts": {
            "true_positives": 1,
            "false_positives": 1,
            "true_negatives": 0,
            "false_negatives": 0,
        },
        "selected_scenario_precision": 0.5,
        "selected_scenario_recall": 1.0,
        "replica_heldout_target_agreement": report["evaluation"][
            "heldout_target_agreement"
        ],
        "majority_baseline_agreement": report["evaluation"][
            "majority_baseline_agreement"
        ],
        "limitations": [
            "Two deliberately selected scenarios are not representative",
            "No population-level detection performance claim",
            "Volume alone did not distinguish intent",
            "Successful requests do not prove model extraction",
            "Model imitation and detection are separate measurements",
        ],
    }

    destination = Path(
        "evidence/public/query-volume-scenario-comparison.json"
    )
    destination.write_text(
        json.dumps(assessment, indent=2) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(assessment, indent=2))
    print("Replication detection assessment: 3/3 passed")

if __name__ == "__main__":
    main()