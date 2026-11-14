"""
Project 10 — Evidence-linked investigation case for H04 / DET-003.

Reconstructs observed activity and delivery timestamps.
Does not infer intent from volume or execute a response action.
"""

import json
import sqlite3
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

from scripts.assess_query_volume_holdout import threshold_crossing
from src.detection.catalog import SUSTAINED_QUERY_RULE
from src.detection.model_access import utc_timestamp
from src.detection.store import validate_finding
from src.telemetry.ingestion import parse_event
from src.telemetry.loki import NoRedirects, collection_timestamp_ns


CASE_ID = "CASE-H04-DET003"
DIRECTORY = Path("evidence/public/investigations")


def get_json(opener, request):
    with opener.open(request, timeout=10) as response:
        raw = response.read(1_048_577)
        if response.status != 200 or len(raw) > 1_048_576:
            raise RuntimeError("Unexpected investigation response")
        return json.loads(raw)


def main():
    json_path = DIRECTORY / f"{CASE_ID}.json"
    markdown_path = DIRECTORY / f"{CASE_ID}.md"

    if json_path.exists() or markdown_path.exists():
        raise RuntimeError("Existing case preserved without overwriting")

    assessment = json.loads(
        Path(
            "evidence/public/query-volume-holdout-assessment.json"
        ).read_text(encoding="utf-8")
    )
    run = json.loads(
        Path(
            "evidence/public/query-volume-holdout-run.json"
        ).read_text(encoding="utf-8")
    )

    scenario = next(
        item for item in run["scenarios"]
        if item["scenario_id"] == "H04"
    )
    assessed = next(
        item for item in assessment["scenarios"]
        if item["scenario_id"] == "H04"
    )

    if (
        assessed["assessment_status"] != "assessed"
        or not assessed["rules"]["DET-003"]["finding_delivered"]
    ):
        raise RuntimeError("A validated delivered finding is required")

    finding_id = assessed["rules"]["DET-003"]["finding_ids"][0]
    key = (
        Path.home()
        / ".config/project10/credentials/finding-receiver-key"
    ).read_text(encoding="utf-8")

    opener = build_opener(ProxyHandler({}), NoRedirects())
    stored = get_json(
        opener,
        Request(
            "http://127.0.0.1:8300/findings/" + finding_id,
            headers={"Authorization": f"Bearer {key}"},
        ),
    )
    finding = stored["finding"]
    validate_finding(finding)

    if finding["finding_id"] != finding_id:
        raise RuntimeError("Finding identity mismatch")

    database = (
        Path.home()
        / ".local/share/project10/monitoring/outbox.sqlite3"
    )
    with closing(sqlite3.connect(
        database.as_uri() + "?mode=ro",
        uri=True,
    )) as connection:
        row = connection.execute(
            """
            SELECT payload_json, queued_at, delivered_at
            FROM finding_outbox WHERE finding_id = ?
            """,
            (finding_id,),
        ).fetchone()

    if row is None or row[2] is None or json.loads(row[0]) != finding:
        raise RuntimeError("Outbox evidence does not match the stored finding")

    started = utc_timestamp(scenario["started_at"])
    completed = utc_timestamp(scenario["traffic_completed_at"])
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
            (completed + timedelta(seconds=1)).isoformat()
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
        raise RuntimeError("Source event query failed")

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
            raise RuntimeError("Unexpected investigation event")

        record = {
            "event_id": event.event_id,
            "request_id": event.request_id,
            "producer_event_time": event.event_time,
            "collected_at": collected_at,
        }
        if event.event_id in events and events[event.event_id] != record:
            raise RuntimeError("Conflicting duplicate event")
        events[event.event_id] = record

    expected_requests = {
        item["request_id"] for item in scenario["observations"]
    }
    if (
        len(events) != 36
        or {item["request_id"] for item in events.values()}
        != expected_requests
        or not set(finding["event_ids"]).issubset(events)
    ):
        raise RuntimeError("Case source evidence is incomplete or mixed")

    crossing = threshold_crossing(
        [
            utc_timestamp(item["collected_at"])
            for item in events.values()
        ],
        SUSTAINED_QUERY_RULE.threshold,
        SUSTAINED_QUERY_RULE.window_seconds,
    )
    if crossing is None:
        raise RuntimeError("Supporting events do not cross the rule threshold")

    timeline = [
        {
            "timestamp": item["collected_at"],
            "kind": "inference_observed",
            "reference": item["event_id"],
            "request_id": item["request_id"],
            "producer_event_time": item["producer_event_time"],
            "contributes_to_selected_finding": (
                item["event_id"] in finding["event_ids"]
            ),
        }
        for item in events.values()
    ]
    timeline.extend([
        {
            "timestamp": crossing.isoformat(),
            "kind": "threshold_crossed",
            "reference": "30 successful requests within 180 seconds",
        },
        {
            "timestamp": finding["detected_at"],
            "kind": "finding_detected",
            "reference": finding_id,
        },
        {
            "timestamp": row[1],
            "kind": "finding_queued",
            "reference": finding_id,
        },
        {
            "timestamp": stored["received_at"],
            "kind": "receiver_stored",
            "reference": finding_id,
        },
        {
            "timestamp": row[2],
            "kind": "outbox_acknowledged",
            "reference": finding_id,
        },
    ])
    timeline.sort(key=lambda item: utc_timestamp(item["timestamp"]))

    case = {
        "case_id": CASE_ID,
        "status": "awaiting_analyst_review",
        "scenario_id": "H04",
        "finding": finding,
        "observed_inference_requests": len(events),
        "timeline": timeline,
        "monitoring_evidence": {
            "source": "actual local inference requests",
            "recorded_monitor_coverage": assessed["monitor_coverage"],
        },
        "declared_exercise_context": {
            "ground_truth": scenario["ground_truth"],
            "replica_evaluation": scenario.get("replica_evaluation"),
            "source": "controlled runner report, not inferred from telemetry",
        },
        "interpretation": {
            "supported": [
                "Authenticated caller repeatedly invoked the model",
                "The sustained-volume condition was met",
                "The finding reached durable receiver storage",
            ],
            "not_established_by_security_events": [
                "Caller intent",
                "Downstream training of a replica",
                "Complete model extraction or weight theft",
            ],
            "alternative_explanation": (
                "Approved bulk processing can trigger the same volume rule"
            ),
        },
        "response": {
            "status": "not_authorized_or_executed",
            "next_action": (
                "Review authorization and exercise context before "
                "deciding whether containment is justified"
            ),
        },
        "evidence_references": [
            "../query-volume-holdout-run.json",
            "../query-volume-holdout-assessment.json",
            "../holdout-monitor.jsonl",
        ],
    }

    DIRECTORY.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(case, indent=2) + "\n",
        encoding="utf-8",
    )

    markdown = [
        f"# {CASE_ID} — Sustained Inference Querying",
        "",
        "**Status:** Awaiting analyst review.",
        "",
        "## Observed Activity",
        "",
        f"- Actual inference requests verified: {len(events)}.",
        f"- Rule: {finding['rule_id']}.",
        f"- Finding ID: `{finding_id}`.",
        "- The finding was queued, stored by the receiver, and acknowledged.",
        "",
        "## Interpretation",
        "",
        "Telemetry establishes sustained authenticated querying. It does not",
        "establish intent or downstream use of model outputs.",
        "",
        "The controlled runner separately identifies this as authorized",
        "adversarial emulation and records replica evaluation results.",
        "Approved bulk processing is a demonstrated alternative explanation.",
        "",
        "## Timeline",
        "",
        "| UTC timestamp | Observation | Evidence reference |",
        "|---|---|---|",
    ]
    for item in timeline:
        markdown.append(
            f"| {item['timestamp']} | {item['kind']} | "
            f"`{item['reference']}` |"
        )

    markdown.extend([
        "",
        "## Response",
        "",
        "No containment action has been authorized or executed by this script.",
        "Review caller authorization, approved activity, and supporting evidence.",
        "",
        "## Evidence",
        "",
        f"- [Structured case]({CASE_ID}.json)",
        "- [Held-out run](../query-volume-holdout-run.json)",
        "- [Held-out assessment](../query-volume-holdout-assessment.json)",
        "- [Monitor coverage](../holdout-monitor.jsonl)",
        "",
        "## Limitations",
        "",
        "- This is a controlled local laboratory case.",
        "- Scenario intent comes from exercise ground truth.",
        "- The timeline is not tamper-evident or independently time-attested.",
        "- Volume alone does not justify automatic containment.",
        "",
    ])
    markdown_path.write_text(
        "\n".join(markdown),
        encoding="utf-8",
    )

    print("PASS: all 36 scenario requests verified")
    print("PASS: finding, outbox, and receiver evidence agree")
    print("PASS: threshold and delivery timeline reconstructed")
    print("Investigation case created:", CASE_ID)
    print("Status: awaiting analyst review; no response executed")

if __name__ == "__main__":
    main()