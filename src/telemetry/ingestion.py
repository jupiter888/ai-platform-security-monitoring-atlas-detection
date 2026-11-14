"""
Project 10 — Strict security event ingestion.

Validates incoming bytes before they reach storage or detections.
Error messages never include submitted values.
"""

import json
from dataclasses import dataclass
from datetime import datetime, timezone

from src.telemetry.events import SecurityEvent
from src.telemetry.operator_events import OperatorEvent


MAX_EVENT_BYTES = 4096

EVENT_FIELDS = frozenset({
    "schema_version",
    "event_id",
    "event_time",
    "provenance",
    "source",
    "request_id",
    "model",
    "outcome",
    "reason",
    "caller_ref",
})


class InvalidTelemetry(ValueError):
    """Incoming telemetry does not satisfy the event contract."""


def unique_object(pairs):
    result = {}

    for key, value in pairs:
        if key in result:
            raise InvalidTelemetry("Duplicate telemetry field")
        result[key] = value

    return result


def reject_constant(_value):
    raise InvalidTelemetry("Invalid JSON constant")


@dataclass(frozen=True)
class CollectedEvent:
    event: SecurityEvent | OperatorEvent
    collected_at: str

    def to_json(self) -> str:
        payload = json.loads(self.event.to_json())
        payload["collected_at"] = self.collected_at

        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        )


def parse_event(raw: bytes) -> CollectedEvent:
    if not isinstance(raw, bytes):
        raise InvalidTelemetry("Telemetry must be bytes")

    if not raw or len(raw) > MAX_EVENT_BYTES:
        raise InvalidTelemetry("Invalid telemetry size")

    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except InvalidTelemetry:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise InvalidTelemetry("Invalid telemetry JSON") from None

    if not isinstance(payload, dict):
        raise InvalidTelemetry("Telemetry must be an object")

    if payload.get("schema_version") == "operator/1.0":
        try:
            event = OperatorEvent(**payload)
        except (TypeError, ValueError):
            raise InvalidTelemetry("Invalid operator telemetry contract") from None
        return CollectedEvent(
            event=event,
            collected_at=datetime.now(timezone.utc).isoformat(),
        )

    if set(payload) != EVENT_FIELDS:
        raise InvalidTelemetry("Unexpected telemetry fields")

    for name, value in payload.items():
        if name == "caller_ref" and value is None:
            continue

        if not isinstance(value, str):
            raise InvalidTelemetry("Invalid telemetry field type")

        if len(value) > 128:
            raise InvalidTelemetry("Telemetry field too long")

    try:
        event = SecurityEvent(**payload)
    except (TypeError, ValueError):
        raise InvalidTelemetry("Invalid telemetry contract") from None

    return CollectedEvent(
        event=event,
        collected_at=datetime.now(timezone.utc).isoformat(),
    )