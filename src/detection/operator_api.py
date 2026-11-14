"""
Project 10 — Authenticated local investigation workflow API.

Containment execution requires a responder and an approved stored scope.
"""

import json
import re
import sqlite3
from pathlib import Path
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from src.detection.cases import CaseLedger
from src.detection.operator_audit import install_operator_audit
from src.telemetry.operator_publisher import OperatorPublisher
from src.detection.containment import ContainmentController
from src.detection.operator_auth import OperatorAuthenticator
from src.detection.store import FindingStore
from src.telemetry.ingestion import reject_constant, unique_object


MAX_OPERATION_BYTES = 4096


def create_app(authenticator=None, ledger=None, audit_publisher=None):
    if authenticator is None:
        directory = Path.home() / ".config/project10/credentials"
        configuration = json.loads(
            (directory / "operators.json").read_text(encoding="utf-8")
        )
        receiver_key = (
            directory / "finding-receiver-key"
        ).read_text(encoding="utf-8")
        authenticator = OperatorAuthenticator(
            configuration,
            forbidden_keys=(receiver_key,),
        )

    if ledger is None:
        directory = Path.home() / ".local/share/project10/monitoring"
        ledger = CaseLedger(
            directory / "cases.sqlite3",
            FindingStore(directory / "findings.sqlite3"),
        )

    controller = ContainmentController(ledger)

    app = FastAPI(
        title="Project 10 Operator Workflow",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    publish = (
        OperatorPublisher().send
        if audit_publisher is None else audit_publisher
    )
    install_operator_audit(app, publish)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request, _exception):
        return JSONResponse(
            status_code=422,
            content={"detail": "Invalid request"},
        )

    def actor_for(request, required_role=None):
        values = request.headers.getlist("authorization")
        actor = (
            authenticator.authenticate(values[0])
            if len(values) == 1
            else None
        )
        if actor is None:
            raise HTTPException(401, "Operator authentication failed")

        request.state.audit_actor = actor

        if required_role is not None and actor.role != required_role:
            raise HTTPException(403, "Operator authorization denied")

        return actor

    def check_case_id(case_id):
        try:
            parsed = UUID(case_id)
        except ValueError:
            raise HTTPException(404, "Case not found") from None

        if parsed.version != 4 or str(parsed) != case_id:
            raise HTTPException(404, "Case not found")

    async def body(request):
        if request.headers.get("content-type", "").lower() != (
            "application/json"
        ):
            raise HTTPException(415, "Content type must be application/json")

        raw = bytearray()
        async for chunk in request.stream():
            if len(raw) + len(chunk) > MAX_OPERATION_BYTES:
                raise HTTPException(413, "Operation exceeds size limit")
            raw.extend(chunk)

        try:
            payload = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            )
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise HTTPException(400, "Invalid operation") from None

        if not isinstance(payload, dict):
            raise HTTPException(400, "Invalid operation")

        return payload

    async def apply(operation, *args):
        try:
            return await run_in_threadpool(operation, *args)
        except PermissionError:
            raise HTTPException(403, "Operator authorization denied") from None
        except LookupError:
            raise HTTPException(404, "Case or finding not found") from None
        except ValueError:
            raise HTTPException(409, "Case operation rejected") from None
        except (RuntimeError, sqlite3.Error):
            raise HTTPException(503, "Case storage unavailable") from None

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/cases", status_code=201)
    async def open_case(request: Request):
        actor = actor_for(request, "analyst")
        payload = await body(request)

        finding_id = payload.get("finding_id")
        if (
            set(payload) != {"finding_id"}
            or not isinstance(finding_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", finding_id) is None
        ):
            raise HTTPException(400, "Invalid operation")

        result = await apply(ledger.open_case, finding_id, actor)
        request.state.audit_case_ref = result["case_id"]
        return result

    @app.get("/cases/{case_id}")
    async def get_case(case_id: str, request: Request):
        actor_for(request)
        check_case_id(case_id)

        result = await apply(ledger.get, case_id)
        if result is None:
            raise HTTPException(404, "Case not found")
        return result

    @app.post("/cases/{case_id}/close-benign")
    async def close_benign(case_id: str, request: Request):
        actor = actor_for(request, "analyst")
        check_case_id(case_id)

        if await body(request) != {"disposition": "approved_activity"}:
            raise HTTPException(400, "Invalid operation")

        return await apply(ledger.close_benign, case_id, actor)

    @app.post("/cases/{case_id}/request-containment")
    async def request_containment(case_id: str, request: Request):
        actor = actor_for(request, "analyst")
        check_case_id(case_id)

        if await body(request) != {"purpose": "controlled_exercise"}:
            raise HTTPException(400, "Invalid operation")

        return await apply(ledger.request_containment, case_id, actor)

    @app.post("/cases/{case_id}/approve-containment")
    async def approve_containment(case_id: str, request: Request):
        actor = actor_for(request, "approver")
        check_case_id(case_id)

        if await body(request) != {"purpose": "controlled_exercise"}:
            raise HTTPException(400, "Invalid operation")

        return await apply(ledger.approve_containment, case_id, actor)

    @app.post("/cases/{case_id}/execute-containment")
    async def execute_containment(case_id: str, request: Request):
        actor = actor_for(request, "responder")
        check_case_id(case_id)
        if await body(request) != {"purpose": "controlled_exercise"}:
            raise HTTPException(400, "Invalid operation")
        return await apply(controller.execute, case_id, actor)

    return app