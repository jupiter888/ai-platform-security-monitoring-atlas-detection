"""
Project 10 — Live DET-002 threshold and benign-batch evaluation.

Scenario ground truth remains outside the detector's input.
Actual predictions are requested through the authenticated API.
"""

import json
import math
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener
from uuid import UUID

from src.detection.model_access import detect_query_volume
from src.telemetry.ingestion import CollectedEvent, parse_event
from src.telemetry.loki import NoRedirects


SELECTOR = (
    '{job="p10-security",source="gateway",provenance="live-lab"}'
    ' | json'
    ' | reason="inference_succeeded"'
    ' | caller_ref="lab-caller-reader"'
    ' | model="research-model"'
)

TOPICS = (
    "A telescope observes planets and distant stars",
    "Plant roots absorb water and nutrients",
    "Volcanic rock forms when magma cools",
)


def request_json(opener, request):
    try:
        response = opener.open(request, timeout=10)
    except HTTPError as error:
        response = error

    with response:
        raw = response.read(524289)
        if len(raw) > 524288:
            raise RuntimeError("Validation response too large")
        return response.code, dict(response.headers), json.loads(raw)


def query_records(opener, start_ns):
    parameters = urlencode({
        "query": SELECTOR,
        "start": str(start_ns),
        "end": str(time.time_ns()),
        "direction": "forward",
        "limit": "500",
    })
    status, _, payload = request_json(
        opener,
        Request(
            "http://127.0.0.1:3100/loki/api/v1/query_range?"
            + parameters
        ),
    )
    if status != 200 or payload.get("status") != "success":
        raise RuntimeError("Loki query failed")

    lines = [
        line
        for stream in payload["data"]["result"]
        for _, line in stream["values"]
    ]
    if len(lines) >= 500:
        raise RuntimeError("Query limit reached")

    records = []
    for line in lines:
        body = json.loads(line)
        collected_at = body.pop("collected_at")
        validated = parse_event(json.dumps(body).encode("utf-8"))
        records.append(CollectedEvent(
            event=validated.event,
            collected_at=collected_at,
        ))

    return records


def wait_for_events(opener, start_ns, expected_ids):
    deadline = time.monotonic() + 20

    while time.monotonic() < deadline:
        records = query_records(opener, start_ns)
        observed = {record.event.request_id for record in records}

        if observed - expected_ids:
            raise RuntimeError("Unrelated requests entered the exercise")

        if observed == expected_ids:
            return records

        time.sleep(1)

    raise RuntimeError("Expected inference events were not queryable in time")


def infer(opener, key, number):
    prompt = (
        f"Research batch item {number}: "
        + TOPICS[(number - 1) % len(TOPICS)]
    )
    status, headers, payload = request_json(
        opener,
        Request(
            "http://127.0.0.1:8200/v1/inference",
            data=json.dumps({
                "model": "research-model",
                "prompt": prompt,
            }).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {key}",
            },
            method="POST",
        ),
    )

    if (
        status != 200
        or payload.get("model") != "research-model"
        or payload.get("label") not in {
            "astronomy", "botany", "geology"
        }
        or type(payload.get("score")) not in (int, float)
        or not math.isfinite(payload["score"])
        or not 0 <= payload["score"] <= 1
    ):
        raise RuntimeError("Actual inference request failed")

    request_id = next(
        (
            value
            for name, value in headers.items()
            if name.lower() == "x-request-id"
        ),
        "",
    )
    parsed = UUID(request_id)
    if parsed.version != 4 or str(parsed) != request_id:
        raise RuntimeError("Invalid correlation identifier")

    return request_id


def main():
    credentials_directory = (
        Path.home() / ".config/project10/credentials"
    )
    clients = json.loads(
        (credentials_directory / "inference-clients.json").read_text(
            encoding="utf-8"
        )
    )
    receiver_key = (
        credentials_directory / "finding-receiver-key"
    ).read_text(encoding="utf-8")

    opener = build_opener(ProxyHandler({}), NoRedirects())

    previous = query_records(
        opener,
        time.time_ns() - 60_000_000_000,
    )
    if previous:
        raise RuntimeError(
            "Recent successful requests remain: wait until 60 seconds "
            "after the last Reader research-model request, then retry"
        )
    print("PASS: successful-query window is clear")

    start_ns = time.time_ns()
    request_ids = set()

    for number in range(1, 20):
        request_ids.add(infer(opener, clients["reader_key"], number))
        time.sleep(0.15)

    if len(request_ids) != 19:
        raise RuntimeError("Repeated request correlation identifier")
    print("PASS: 19 actual model predictions completed")

    records = wait_for_events(opener, start_ns, request_ids)
    findings = detect_query_volume(
        records,
        as_of=datetime.now(timezone.utc),
    )
    if findings:
        raise RuntimeError("DET-002 triggered below its threshold")
    print("PASS: 19 successful requests produce no DET-002 finding")

    request_ids.add(infer(opener, clients["reader_key"], 20))
    if len(request_ids) != 20:
        raise RuntimeError("Repeated request correlation identifier")
    print("PASS: twentieth actual model prediction completed")

    records = wait_for_events(opener, start_ns, request_ids)
    findings = detect_query_volume(
        records,
        as_of=datetime.now(timezone.utc),
    )
    if len(findings) != 1 or findings[0]["event_count"] != 20:
        raise RuntimeError("Expected one 20-event DET-002 finding")

    finding = findings[0]
    if set(finding["event_ids"]) != {
        record.event.event_id for record in records
    }:
        raise RuntimeError("Finding evidence does not match the requests")
    print("PASS: 20 successful requests produce an evidence-linked finding")

    endpoint = (
        "http://127.0.0.1:8300/findings/"
        + finding["finding_id"]
    )
    deadline = time.monotonic() + 30

    while time.monotonic() < deadline:
        status, _, stored = request_json(
            opener,
            Request(
                endpoint,
                headers={
                    "Authorization": f"Bearer {receiver_key}",
                },
            ),
        )

        if status == 200:
            received = stored["finding"]
            for field in (
                "finding_id",
                "rule_id",
                "caller_ref",
                "model",
                "event_count",
                "event_ids",
            ):
                if received[field] != finding[field]:
                    raise RuntimeError("Stored finding evidence mismatch")
            break

        if status != 404:
            raise RuntimeError("Finding retrieval failed")
        time.sleep(1)
    else:
        raise RuntimeError(
            "Continuous monitor did not deliver the finding in time"
        )

    print("PASS: continuous monitor delivered DET-002 to durable storage")
    print(json.dumps({
        "scenario": "approved-research-batch",
        "ground_truth": "benign",
        "successful_predictions": 20,
        "rule_id": "DET-002",
        "finding_id": finding["finding_id"],
        "rule_condition_met": True,
        "operational_false_positive_observed": True,
        "interpretation": (
            "The volume condition was detected correctly, but volume "
            "alone did not distinguish approved activity from abuse."
        ),
    }, indent=2))
    print("Live query-volume validation: 6/6 passed")
    print("Scope: one controlled benign batch; no population-level rate claim")

if __name__ == "__main__":
    main()