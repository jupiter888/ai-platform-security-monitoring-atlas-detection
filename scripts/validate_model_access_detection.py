"""
Project 10 — DET-001 live integration validation.

Actual unauthorized requests:
API -> collector -> Loki -> detection evaluation.

The exercise isolates its time range and fails if unrelated matching
requests enter that range. The detector receives collected events,
not expected classifications or scenario labels.

No continuous detection scheduling or alert delivery is implemented here.
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)
from uuid import UUID

from src.detection.model_access import detect_model_access
from src.telemetry.ingestion import CollectedEvent, parse_event


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_json(opener, request):
    try:
        response = opener.open(request, timeout=10)
    except HTTPError as error:
        response = error

    with response:
        raw = response.read(524289)
        if len(raw) > 524288:
            raise RuntimeError("Validation response exceeds size limit")

        return response.code, dict(response.headers), json.loads(raw)


def send_denied_request(opener, reader_key):
    request = Request(
        "http://127.0.0.1:8200/v1/inference",
        data=json.dumps({
            "model": "restricted-model",
            "prompt": "Synthetic access-control detection exercise",
        }).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {reader_key}",
        },
        method="POST",
    )

    status, headers, payload = read_json(opener, request)

    if status != 403 or payload != {"detail": "Model access denied"}:
        raise RuntimeError("Expected model-access denial contract")

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
        raise RuntimeError("Invalid request correlation identifier")

    return request_id


def fetch_records(opener, start_ns, expected_request_ids):
    expression = (
        '{job="p10-security",source="gateway",provenance="live-lab"}'
        ' | json'
        ' | reason="model_access_denied"'
        ' | caller_ref="lab-caller-reader"'
        ' | model="restricted-model"'
    )
    deadline = time.monotonic() + 20

    while time.monotonic() < deadline:
        parameters = urlencode({
            "query": expression,
            "start": str(start_ns),
            "end": str(time.time_ns()),
            "direction": "forward",
            "limit": "500",
        })
        status, _, result = read_json(
            opener,
            Request(
                "http://127.0.0.1:3100/loki/api/v1/query_range?"
                + parameters
            ),
        )

        if status != 200 or result.get("status") != "success":
            raise RuntimeError("Loki event query failed")

        lines = [
            line
            for stream in result["data"]["result"]
            for _, line in stream["values"]
        ]
        if len(lines) >= 500:
            raise RuntimeError("Query limit reached; completeness not established")

        records = []
        for line in lines:
            payload = json.loads(line)
            collected_at = payload.pop("collected_at")
            validated = parse_event(
                json.dumps(payload).encode("utf-8")
            )
            records.append(CollectedEvent(
                event=validated.event,
                collected_at=collected_at,
            ))

        observed = {
            record.event.request_id
            for record in records
        }

        if observed - expected_request_ids:
            raise RuntimeError(
                "Unrelated matching requests entered the exercise window"
            )

        if observed == expected_request_ids:
            return records

        time.sleep(1)

    raise RuntimeError("Expected request events were not queryable in time")


def evaluate(records):
    return detect_model_access(
        records,
        as_of=datetime.now(timezone.utc),
    )


def main():
    path = (
        Path.home()
        / ".config/project10/credentials/inference-clients.json"
    )
    credentials = json.loads(path.read_text(encoding="utf-8"))
    reader_key = credentials["reader_key"]

    opener = build_opener(ProxyHandler({}), NoRedirects())
    start_ns = time.time_ns()
    request_ids = set()

    for _ in range(4):
        request_ids.add(send_denied_request(opener, reader_key))

    if len(request_ids) != 4:
        raise RuntimeError("Request correlation identifiers repeated")

    print("PASS: four actual restricted-model requests denied")

    records = fetch_records(opener, start_ns, request_ids)
    findings = evaluate(records)

    if findings:
        raise RuntimeError("Finding generated below the five-event threshold")

    print("PASS: four denials produce no DET-001 finding")

    fifth_id = send_denied_request(opener, reader_key)
    if fifth_id in request_ids:
        raise RuntimeError("Request correlation identifier repeated")
    request_ids.add(fifth_id)

    print("PASS: fifth actual restricted-model request denied")

    records = fetch_records(opener, start_ns, request_ids)
    findings = evaluate(records)

    if len(findings) != 1:
        raise RuntimeError("Expected exactly one DET-001 finding")

    finding = findings[0]
    expected_event_ids = {
        record.event.event_id
        for record in records
    }

    if (
        finding["rule_id"] != "DET-001"
        or finding["event_count"] != 5
        or finding["caller_ref"] != "lab-caller-reader"
        or finding["model"] != "restricted-model"
        or set(finding["event_ids"]) != expected_event_ids
        or len(expected_event_ids) != 5
    ):
        raise RuntimeError("Finding evidence does not match observed events")

    print("PASS: five denials produce one evidence-linked DET-001 finding")
    print(json.dumps(finding, indent=2))
    print("Live model-access detection validation: 4/4 passed")
    print("Mode: one-shot evaluation of an isolated live exercise window")
    print("No continuous monitoring or notification delivery claimed")

if __name__ == "__main__":
    main()