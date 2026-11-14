"""
Project 10 — Live collector-to-Loki validation.

Submits synthetic heartbeats and queries their exact event IDs.
Does not execute attacks or validate detection rules.
"""

import json
import time
from datetime import datetime
from urllib.parse import urlencode
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)
from uuid import uuid4

from src.telemetry.events import create_event
from src.telemetry.producer_credentials import load_producer_key


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_json(opener, request):
    with opener.open(request, timeout=5) as response:
        raw = response.read(524289)
        if len(raw) > 524288:
            raise RuntimeError("Response exceeds validation limit")
        return response.status, json.loads(raw)


def main():
    opener = build_opener(ProxyHandler({}), NoRedirects())
    request_id = str(uuid4())
    start_ns = time.time_ns() - 5_000_000_000
    expected = {}

    for _ in range(3):
        event = create_event(
            provenance="synthetic",
            source="collector",
            model="not-applicable",
            reason="heartbeat",
            request_id=request_id,
        )
        payload = json.loads(event.to_json())
        expected[event.event_id] = payload

        request = Request(
            "http://127.0.0.1:8100/events",
            data=event.to_json().encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": (
                    "Bearer " + load_producer_key("fixture")
                ),
            },
            method="POST",
        )
        status, _ = read_json(opener, request)
        if status != 202:
            raise RuntimeError("Collector did not accept validation event")

    print("PASS: three synthetic heartbeats accepted")

    expression = (
        '{job="p10-security",source="collector",provenance="synthetic"}'
        ' | json'
        f' | request_id="{request_id}"'
    )

    records = []
    deadline = time.monotonic() + 20

    while time.monotonic() < deadline:
        parameters = urlencode({
            "query": expression,
            "start": str(start_ns),
            "end": str(time.time_ns()),
            "direction": "forward",
            "limit": "100",
        })
        _, result = read_json(
            opener,
            Request(
                "http://127.0.0.1:3100/loki/api/v1/query_range?"
                + parameters
            ),
        )

        if result.get("status") != "success":
            raise RuntimeError("Loki query failed")

        records = [
            json.loads(line)
            for stream in result["data"]["result"]
            for _, line in stream["values"]
        ]

        observed_ids = {record.get("event_id") for record in records}
        if set(expected).issubset(observed_ids):
            break

        time.sleep(1)
    else:
        raise RuntimeError("Submitted events were not queryable in time")

    print("PASS: all three submitted event IDs are queryable in Loki")

    for record in records:
        event_id = record.get("event_id")
        if event_id not in expected:
            raise RuntimeError("Unexpected event in validation result")

        if set(record) != set(expected[event_id]) | {"collected_at"}:
            raise RuntimeError("Stored event fields differ from contract")

        for field, value in expected[event_id].items():
            if record[field] != value:
                raise RuntimeError("Stored event content changed")

        timestamp = datetime.fromisoformat(record["collected_at"])
        if timestamp.tzinfo is None or timestamp.utcoffset().total_seconds() != 0:
            raise RuntimeError("Invalid stored collection timestamp")

    print("PASS: stored fields match submitted events and collection contract")
    print(f"Matching log records: {len(records)}; distinct expected events: 3")
    print("Collector-to-Loki validation: 3/3 passed")
    print("Provenance: synthetic heartbeat telemetry")

if __name__ == "__main__":
    main()