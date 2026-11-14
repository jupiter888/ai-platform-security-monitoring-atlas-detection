"""Audit supported operator routes without recording submitted content."""

import json
from uuid import UUID, uuid4

from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from src.detection.cases import Actor
from src.telemetry.operator_events import create_operator_event


OPERATIONS = {
    "open_case": "case_open",
    "get_case": "case_read",
    "close_benign": "case_close_benign",
    "request_containment": "containment_request",
    "approve_containment": "containment_approve",
    "execute_containment": "containment_execute",
}


def canonical_case(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = UUID(value)
    except ValueError:
        return None
    return value if parsed.version == 4 and str(parsed) == value else None


def decision_reason(status):
    if 200 <= status < 300:
        return "operation_succeeded"
    return {
        401: "authentication_failed",
        403: "authorization_denied",
        404: "not_found",
        409: "state_conflict",
        503: "storage_unavailable",
    }.get(
        status,
        "handler_failure" if status >= 500 else "invalid_operation",
    )


def install_operator_audit(app, publisher):
    @app.middleware("http")
    async def audit_operation(request, call_next):
        request_id = str(uuid4())

        try:
            response = await call_next(request)
        except Exception:
            response = JSONResponse(
                status_code=500,
                content={"detail": "Operator operation failed"},
            )

        route = request.scope.get("route")
        operation = OPERATIONS.get(getattr(route, "name", None))
        if operation is None:
            return response

        actor = getattr(request.state, "audit_actor", None)
        if not isinstance(actor, Actor):
            actor = None

        reason = decision_reason(response.status_code)
        if reason == "authentication_failed":
            actor = None

        case_ref = canonical_case(
            getattr(request.state, "audit_case_ref", None)
        )
        if case_ref is None:
            case_ref = canonical_case(
                request.path_params.get("case_id")
            )

        event = create_operator_event(
            operation=operation,
            reason=reason,
            request_id=request_id,
            actor_ref=None if actor is None else actor.subject,
            actor_role=None if actor is None else actor.role,
            case_ref=case_ref,
        )

        try:
            accepted = (
                await run_in_threadpool(publisher, event)
            ) is True
        except Exception:
            accepted = False

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Audit-Delivery"] = (
            "buffered" if accepted else "unavailable"
        )

        if not accepted:
            # A console fallback is not a durable delivery guarantee.
            record = {
                "event": "operator_audit_delivery_failed",
                "audit_event": json.loads(event.to_json()),
            }
            try:
                print(json.dumps(record, sort_keys=True), flush=True)
            except OSError:
                pass

        return response