"""Aggregate invalid-credential activity without caller attribution."""

import hashlib
import json
from datetime import timedelta

from src.detection.catalog import AUTH_FAILURE_RULE
from src.detection.model_access import utc_timestamp


def detect_authentication_failures(records, *, as_of):
    if as_of.tzinfo is None or as_of.utcoffset() != timedelta(0):
        raise ValueError("Evaluation time must use UTC")

    rule = AUTH_FAILURE_RULE
    lower = as_of - timedelta(seconds=rule.window_seconds)
    seen = {}
    matching = []

    for record in records:
        event = record.event
        if (
            event.source != "gateway"
            or event.provenance != "live-lab"
            or event.reason != rule.reason
            or event.outcome != rule.outcome
            or event.caller_ref is not None
        ):
            continue

        collected_at = utc_timestamp(record.collected_at)
        if not lower < collected_at <= as_of:
            continue

        serialized = record.to_json()
        if event.event_id in seen:
            if seen[event.event_id] != serialized:
                raise ValueError("Conflicting duplicate event ID")
            continue

        seen[event.event_id] = serialized
        matching.append((collected_at, event.event_id))

    if len(matching) < rule.threshold:
        return []

    matching.sort()
    event_ids = [event_id for _, event_id in matching]
    identity = {
        "rule_id": rule.rule_id,
        "rule_version": rule.version,
        "caller_ref": None,
        "model": "not-applicable",
        "event_ids": event_ids,
    }
    finding_id = hashlib.sha256(
        json.dumps(
            identity, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()

    return [{
        **identity,
        "finding_id": finding_id,
        "severity": rule.severity,
        "classification": rule.classification,
        "event_count": len(event_ids),
        "threshold": rule.threshold,
        "window_seconds": rule.window_seconds,
        "first_seen": matching[0][0].isoformat(),
        "last_seen": matching[-1][0].isoformat(),
        "detected_at": as_of.isoformat(),
    }]