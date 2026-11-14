"""Bounded operator audit events, separate from inference telemetry."""

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from src.telemetry.events import validate_uuid


OPERATIONS = frozenset({
    "case_open",
    "case_read",
    "case_close_benign",
    "containment_request",
    "containment_approve",
    "containment_execute",
})

DECISIONS = {
    "operation_succeeded": "allowed",
    "authentication_failed": "denied",
    "authorization_denied": "denied",
    "invalid_operation": "denied",
    "state_conflict": "denied",
    "not_found": "denied",
    "storage_unavailable": "error",
    "handler_failure": "error",
}

OPERATOR_PATTERN = re.compile(r"lab-operator-[a-z0-9]{1,24}")


@dataclass(frozen=True)
class OperatorEvent:
    schema_version: str
    event_id: str
    event_time: str
    provenance: str
    source: str
    request_id: str
    operation: str
    outcome: str
    reason: str
    actor_ref: str | None
    actor_role: str | None
    case_ref: str | None

    def __post_init__(self):
        optional = {"actor_ref", "actor_role", "case_ref"}
        for name, value in asdict(self).items():
            if name in optional and value is None:
                continue
            if not isinstance(value, str) or len(value) > 128:
                raise ValueError("Invalid operator event")

        if self.schema_version != "operator/1.0" or self.source != "operator":
            raise ValueError("Invalid operator event")
        if self.provenance not in {"live-lab", "synthetic", "replay"}:
            raise ValueError("Invalid operator event")

        validate_uuid(self.event_id)
        validate_uuid(self.request_id)

        try:
            timestamp = datetime.fromisoformat(self.event_time)
        except ValueError:
            raise ValueError("Invalid operator event") from None
        if timestamp.tzinfo is None or timestamp.utcoffset() != timedelta(0):
            raise ValueError("Invalid operator event")

        if (
            self.operation not in OPERATIONS
            or self.reason not in DECISIONS
            or self.outcome != DECISIONS[self.reason]
        ):
            raise ValueError("Invalid operator event")

        if (self.actor_ref is None) != (self.actor_role is None):
            raise ValueError("Invalid operator event")
        if self.actor_ref is not None:
            if (
                OPERATOR_PATTERN.fullmatch(self.actor_ref) is None
                or self.actor_role not in {"analyst", "approver", "responder"}
            ):
                raise ValueError("Invalid operator event")
        if self.reason == "authentication_failed" and self.actor_ref is not None:
            raise ValueError("Invalid operator event")
        if self.outcome == "allowed" and self.actor_ref is None:
            raise ValueError("Invalid operator event")
        if self.case_ref is not None:
            validate_uuid(self.case_ref)

    def to_json(self):
        return json.dumps(
            asdict(self), sort_keys=True, separators=(",", ":")
        )


def create_operator_event(
    *,
    operation,
    reason,
    request_id,
    actor_ref=None,
    actor_role=None,
    case_ref=None,
    provenance="live-lab",
):
    if not isinstance(reason, str) or reason not in DECISIONS:
        raise ValueError("Invalid operator event")
    return OperatorEvent(
        schema_version="operator/1.0",
        event_id=str(uuid4()),
        event_time=datetime.now(timezone.utc).isoformat(),
        provenance=provenance,
        source="operator",
        request_id=request_id,
        operation=operation,
        outcome=DECISIONS[reason],
        reason=reason,
        actor_ref=actor_ref,
        actor_role=actor_role,
        case_ref=case_ref,
    )