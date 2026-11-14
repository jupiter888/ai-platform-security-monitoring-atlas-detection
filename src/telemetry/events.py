"""
Project 10 — Versioned security event contract.

Contains bounded, allowlisted metadata only.
Prompts, credentials, tokens, and arbitrary messages are excluded.
"""

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID, uuid4


PROVENANCE = frozenset({
    "live-lab",
    "synthetic",
    "replay",
})

SOURCES = frozenset({
    "gateway",
    "backend",
    "collector",
})

REASON_OUTCOMES = {
    "inference_succeeded": "allowed",
    "authentication_required": "denied",
    "authentication_failed": "denied",
    "model_access_denied": "denied",
    "quota_exceeded": "denied",
    "concurrency_exceeded": "unavailable",
    "backend_unavailable": "unavailable",
    "service_authentication_failed": "denied",
    "invalid_request": "denied",
    "heartbeat": "observed",
    "containment_enforced": "denied",
    "response_policy_unavailable": "unavailable",
}

MODELS = frozenset({
    "research-model",
    "restricted-model",
    "unrecognized",
    "not-applicable",
})

# Only deliberately synthetic identities are accepted.
CALLER_PATTERN = re.compile(r"lab-caller-[a-z0-9]{1,24}")


def validate_uuid(value: str) -> None:
    if not isinstance(value, str):
        raise ValueError("Identifier must be a UUID string")

    try:
        parsed = UUID(value)
    except ValueError:
        raise ValueError("Identifier must be a UUID string") from None

    if str(parsed) != value or parsed.version != 4:
        raise ValueError("Identifier must be a canonical UUID4")


@dataclass(frozen=True)
class SecurityEvent:
    schema_version: str
    event_id: str
    event_time: str
    provenance: str
    source: str
    request_id: str
    model: str
    outcome: str
    reason: str
    caller_ref: str | None

    def __post_init__(self) -> None:
        if self.schema_version != "1.0":
            raise ValueError("Unsupported event schema")

        validate_uuid(self.event_id)
        validate_uuid(self.request_id)

        if not isinstance(self.event_time, str):
            raise ValueError("Invalid event timestamp")

        try:
            timestamp = datetime.fromisoformat(self.event_time)
        except ValueError:
            raise ValueError("Invalid event timestamp") from None

        if (
            timestamp.tzinfo is None
            or timestamp.utcoffset() != timezone.utc.utcoffset(timestamp)
        ):
            raise ValueError("Event timestamp must use UTC")

        if self.provenance not in PROVENANCE:
            raise ValueError("Invalid event provenance")

        if self.source not in SOURCES:
            raise ValueError("Invalid event source")

        if self.model not in MODELS:
            raise ValueError("Invalid model reference")

        if (
            self.reason not in REASON_OUTCOMES
            or REASON_OUTCOMES[self.reason] != self.outcome
        ):
            raise ValueError("Invalid reason and outcome combination")

        if self.caller_ref is not None:
            if (
                not isinstance(self.caller_ref, str)
                or CALLER_PATTERN.fullmatch(self.caller_ref) is None
            ):
                raise ValueError("Invalid synthetic caller reference")

        if self.reason in {
            "authentication_required",
            "authentication_failed",
        } and self.caller_ref is not None:
            raise ValueError("Unauthenticated events cannot identify a caller")

    def to_json(self) -> str:
        return json.dumps(
            {
                "schema_version": self.schema_version,
                "event_id": self.event_id,
                "event_time": self.event_time,
                "provenance": self.provenance,
                "source": self.source,
                "request_id": self.request_id,
                "model": self.model,
                "outcome": self.outcome,
                "reason": self.reason,
                "caller_ref": self.caller_ref,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def create_event(
    *,
    provenance: str,
    source: str,
    model: str,
    reason: str,
    caller_ref: str | None = None,
    request_id: str | None = None,
) -> SecurityEvent:
    if reason not in REASON_OUTCOMES:
        raise ValueError("Invalid event reason")

    return SecurityEvent(
        schema_version="1.0",
        event_id=str(uuid4()),
        event_time=datetime.now(timezone.utc).isoformat(),
        provenance=provenance,
        source=source,
        request_id=str(uuid4()) if request_id is None else request_id,
        model=model,
        outcome=REASON_OUTCOMES[reason],
        reason=reason,
        caller_ref=caller_ref,
    )