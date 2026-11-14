"""
Project 10 — Continuous six-rule detection and durable delivery.

Queries the longest configured observation window.
Pending delivery proceeds independently of successful Loki polling.
"""

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

from src.detection.authentication import detect_authentication_failures
from src.detection.catalog import RULES
from src.detection.operator_detection import detect_operator_denials
from src.detection.metrics import MonitorMetrics, start_metrics_server
from src.detection.model_access import (
    detect_admission_pressure,
    detect_model_access,
    detect_query_volume,
    detect_sustained_query_volume,
)
from src.detection.notification import ReceiverClient
from src.detection.outbox import FindingOutbox
from src.telemetry.ingestion import CollectedEvent, parse_event
from src.telemetry.loki import NoRedirects, collection_timestamp_ns


METRICS = MonitorMetrics()

POLL_INTERVAL_SECONDS = 5
QUERY_LIMIT = 500
MAX_RESPONSE_BYTES = 1_048_576
LOOKBACK_SECONDS = max(rule.window_seconds for rule in RULES.values())


def evaluate_rules(records, *, as_of):
    return (
        detect_model_access(records, as_of=as_of)
        + detect_query_volume(records, as_of=as_of)
        + detect_sustained_query_volume(records, as_of=as_of)
        + detect_authentication_failures(records, as_of=as_of)
        + detect_admission_pressure(records, as_of=as_of)
        + detect_operator_denials(records, as_of=as_of)
    )


def query_records(opener, as_of):
    start = as_of - timedelta(seconds=LOOKBACK_SECONDS)
    expression = (
        '{job="p10-security",source=~"gateway|operator",provenance="live-lab"}'
    )
    parameters = urlencode({
        "query": expression,
        "start": collection_timestamp_ns(start.isoformat()),
        "end": collection_timestamp_ns(as_of.isoformat()),
        "direction": "forward",
        "limit": str(QUERY_LIMIT),
    })
    request = Request(
        "http://127.0.0.1:3100/loki/api/v1/query_range?"
        + parameters
    )

    with opener.open(request, timeout=5) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)

    if len(raw) > MAX_RESPONSE_BYTES:
        raise RuntimeError("Query response exceeds size limit")

    payload = json.loads(raw)
    if (
        payload.get("status") != "success"
        or payload["data"]["resultType"] != "streams"
    ):
        raise RuntimeError("Unexpected query response")

    lines = [
        line
        for stream in payload["data"]["result"]
        for _, line in stream["values"]
    ]

    if len(lines) >= QUERY_LIMIT:
        raise RuntimeError("Query limit reached")

    records = []
    for line in lines:
        event_payload = json.loads(line)
        collected_at = event_payload.pop("collected_at")
        validated = parse_event(
            json.dumps(event_payload).encode("utf-8")
        )
        records.append(CollectedEvent(
            event=validated.event,
            collected_at=collected_at,
        ))

    return records


def deliver_pending(outbox, client, *, limit=10, clock=None):
    if clock is None:
        clock = lambda: datetime.now(timezone.utc)

    result = {"attempted": 0, "failed": 0, "accepted": []}

    for finding in outbox.pending(limit=limit):
        finding_id = finding["finding_id"]
        outbox.record_attempt(finding_id, as_of=clock())
        result["attempted"] += 1

        try:
            receipt = client.send(finding)
        except Exception:
            receipt = None

        if (
            not isinstance(receipt, dict)
            or set(receipt) != {"status", "finding_id", "duplicate"}
            or receipt["status"] != "stored"
            or receipt["finding_id"] != finding_id
            or type(receipt["duplicate"]) is not bool
        ):
            result["failed"] += 1
            continue

        outbox.mark_delivered(finding_id, as_of=clock())
        result["accepted"].append({
            "finding": finding,
            "receipt": receipt,
        })

    return result


def log_record(record):
    if record.get("event") == "detection_poll":
        METRICS.observe(record)
    print(json.dumps(record, sort_keys=True), flush=True)


def main():
    opener = build_opener(ProxyHandler({}), NoRedirects())
    client = ReceiverClient()
    outbox = FindingOutbox(
        Path.home()
        / ".local/share/project10/monitoring/outbox.sqlite3"
    )

    metrics_server = start_metrics_server(METRICS)

    log_record({
        "event": "detection_monitor_started",
        "rule_ids": list(RULES),
        "lookback_seconds": LOOKBACK_SECONDS,
        "poll_interval_seconds": POLL_INTERVAL_SECONDS,
        "suppression_seconds": outbox.cooldown_seconds,
        "output": "durable-outbox-to-local-receiver",
    })

    try:
        while True:
            started = time.monotonic()
            as_of = datetime.now(timezone.utc)

            status = {
                "event": "detection_poll",
                "timestamp": as_of.isoformat(),
                "query_status": "ok",
                "delivery_status": "ok",
                "records_scanned": 0,
                "findings_queued": 0,
                "findings_suppressed": 0,
                "delivery_attempted": 0,
                "delivery_failed": 0,
                "findings_delivered": 0,
            }

            try:
                records = query_records(opener, as_of)
                status["records_scanned"] = len(records)

                for finding in evaluate_rules(records, as_of=as_of):
                    disposition = outbox.enqueue(finding, as_of=as_of)
                    log_record({
                        "event": "finding_enqueue_disposition",
                        "rule_id": finding["rule_id"],
                        "finding_id": finding["finding_id"],
                        "disposition": disposition,
                    })
                    if disposition == "queued":
                        status["findings_queued"] += 1
                    else:
                        status["findings_suppressed"] += 1

            except Exception:
                status["query_status"] = "error"

            try:
                delivery = deliver_pending(outbox, client)
                status["delivery_attempted"] = delivery["attempted"]
                status["delivery_failed"] = delivery["failed"]
                status["findings_delivered"] = len(delivery["accepted"])

                if delivery["failed"]:
                    status["delivery_status"] = "error"

                for accepted in delivery["accepted"]:
                    log_record({
                        "event": "finding_delivery_receipt",
                        **accepted["receipt"],
                    })
                    log_record({
                        "event": "security_finding",
                        "finding": accepted["finding"],
                    })

            except Exception:
                status["delivery_status"] = "error"

            try:
                stats = outbox.stats()
                status["outbox_pending"] = stats["pending"]
                status["outbox_delivered"] = stats["delivered"]
            except Exception:
                status["delivery_status"] = "error"
                status["outbox_pending"] = None
                status["outbox_delivered"] = None

            status["status"] = (
                "ok"
                if (
                    status["query_status"] == "ok"
                    and status["delivery_status"] == "ok"
                )
                else "error"
            )
            log_record(status)

            remaining = POLL_INTERVAL_SECONDS - (
                time.monotonic() - started
            )
            if remaining > 0:
                time.sleep(remaining)

    except KeyboardInterrupt:
        log_record({"event": "detection_monitor_stopped"})
    finally:
        metrics_server.shutdown()
        metrics_server.server_close()

if __name__ == "__main__":
    main()