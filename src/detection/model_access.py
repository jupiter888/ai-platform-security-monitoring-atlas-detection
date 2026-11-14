"""
Project 10 — Windowed inference-security detection.

Uses collector timestamps and distinct event IDs.
Rule matches identify behavior, not malicious intent.
"""

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from src.detection.catalog import (
    ADMISSION_PRESSURE_RULE,
    MODEL_ACCESS_RULE,
    QUERY_VOLUME_RULE,
    SUSTAINED_QUERY_RULE,
)
from src.telemetry.ingestion import CollectedEvent


# Compatibility references for the original DET-001 implementation.
RULE_ID = MODEL_ACCESS_RULE.rule_id
RULE_VERSION = MODEL_ACCESS_RULE.version
WINDOW_SECONDS = MODEL_ACCESS_RULE.window_seconds
THRESHOLD = MODEL_ACCESS_RULE.threshold


def utc_timestamp(value: str) -> datetime:
    timestamp = datetime.fromisoformat(value)

    if (
        timestamp.tzinfo is None
        or timestamp.utcoffset() != timedelta(0)
    ):
        raise ValueError("Detection timestamp must use UTC")

    return timestamp


def _detect(records, *, as_of, rule):
    if (
        as_of.tzinfo is None
        or as_of.utcoffset() != timedelta(0)
    ):
        raise ValueError("Evaluation time must use UTC")

    lower_bound = as_of - timedelta(seconds=rule.window_seconds)
    seen = {}
    groups = defaultdict(list)

    for record in records:
        event = record.event

        if (
            event.source != "gateway"
            or event.provenance != "live-lab"
            or event.reason != rule.reason
            or event.outcome != rule.outcome
            or event.caller_ref is None
            or event.model not in {
                "research-model",
                "restricted-model",
            }
        ):
            continue

        collected_at = utc_timestamp(record.collected_at)
        if not lower_bound < collected_at <= as_of:
            continue

        serialized = record.to_json()
        if event.event_id in seen:
            if seen[event.event_id] != serialized:
                raise ValueError("Conflicting duplicate event ID")
            continue

        seen[event.event_id] = serialized
        groups[(event.caller_ref, event.model)].append(
            (collected_at, event.event_id)
        )

    findings = []

    for (caller, model), matching in sorted(groups.items()):
        if len(matching) < rule.threshold:
            continue

        matching.sort()
        event_ids = [event_id for _, event_id in matching]

        identity = {
            "rule_id": rule.rule_id,
            "rule_version": rule.version,
            "caller_ref": caller,
            "model": model,
            "event_ids": event_ids,
        }
        fingerprint = hashlib.sha256(
            json.dumps(
                identity,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

        findings.append({
            "finding_id": fingerprint,
            "rule_id": rule.rule_id,
            "rule_version": rule.version,
            "severity": rule.severity,
            "classification": rule.classification,
            "caller_ref": caller,
            "model": model,
            "event_count": len(matching),
            "threshold": rule.threshold,
            "window_seconds": rule.window_seconds,
            "first_seen": matching[0][0].isoformat(),
            "last_seen": matching[-1][0].isoformat(),
            "detected_at": as_of.astimezone(timezone.utc).isoformat(),
            "event_ids": event_ids,
        })

    return findings


def detect_model_access(
    records: list[CollectedEvent],
    *,
    as_of: datetime,
) -> list[dict]:
    return _detect(records, as_of=as_of, rule=MODEL_ACCESS_RULE)


def detect_query_volume(
    records: list[CollectedEvent],
    *,
    as_of: datetime,
) -> list[dict]:
    return _detect(records, as_of=as_of, rule=QUERY_VOLUME_RULE)


def detect_sustained_query_volume(
    records: list[CollectedEvent],
    *,
    as_of: datetime,
) -> list[dict]:
    return _detect(records, as_of=as_of, rule=SUSTAINED_QUERY_RULE)

def detect_admission_pressure(records, *, as_of):
    return _detect(records, as_of=as_of, rule=ADMISSION_PRESSURE_RULE)
