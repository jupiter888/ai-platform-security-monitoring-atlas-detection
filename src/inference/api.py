"""
Project 10 — Authenticated local model API.

Local opaque credentials identify synthetic lab callers.
Successful inference requires collector acceptance of its security event.

Both model names currently expose the same classifier under different
access policies. They are not independently trained models.
"""

import hmac
import json
import re
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from src.detection.containment import read_block_status
from src.inference.admission import AdmissionGate
from src.inference.model import MODEL_VERSION, ResearchClassifier
from src.telemetry.events import create_event
from src.telemetry.producer_credentials import load_producer_key
from src.telemetry.loki import NoRedirects


PERMISSIONS = {
    "research-model": frozenset({"Inference.Reader"}),
    "restricted-model": frozenset({"Inference.Admin"}),
}


class InferenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: str = Field(strict=True, min_length=1, max_length=100)
    prompt: str = Field(strict=True, min_length=1, max_length=2000)


def load_credentials():
    path = (
        Path.home()
        / ".config/project10/credentials/inference-clients.json"
    )
    return json.loads(path.read_text(encoding="utf-8"))


def validate_credentials(credentials):
    if (
        not isinstance(credentials, dict)
        or set(credentials) != {"reader_key", "admin_key"}
    ):
        raise RuntimeError("Invalid client credential configuration")

    for value in credentials.values():
        if (
            not isinstance(value, str)
            or re.fullmatch(r"[0-9a-f]{64}", value) is None
        ):
            raise RuntimeError("Invalid client credential configuration")

    if credentials["reader_key"] == credentials["admin_key"]:
        raise RuntimeError("Client credentials must be distinct")

    return dict(credentials)


def publish_event(event, producer_key=None):
    if producer_key is None:
        producer_key = load_producer_key("gateway")
    request = Request(
        "http://127.0.0.1:8100/events",
        data=event.to_json().encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {producer_key}",
        },
        method="POST",
    )
    opener = build_opener(ProxyHandler({}), NoRedirects())

    try:
        with opener.open(request, timeout=2) as response:
            return response.status == 202
    except HTTPError as error:
        error.close()
        return False
    except (URLError, OSError):
        return False


def check_containment(caller_ref, model):
    database = (
        Path.home()
        / ".local/share/project10/monitoring/cases.sqlite3"
    )
    return read_block_status(database, caller_ref, model)


def create_app(
    credentials=None,
    model=None,
    publisher=None,
    access_checker=None,
    admission_limit=2,
):
    credentials = validate_credentials(
        load_credentials() if credentials is None else credentials
    )
    gate = AdmissionGate(admission_limit)
    classifier = ResearchClassifier() if model is None else model
    if publisher is None:
        producer_key = load_producer_key("gateway")
        publish = lambda event: publish_event(
            event, producer_key=producer_key
        )
    else:
        publish = publisher
    check_access = (
        check_containment if access_checker is None else access_checker
    )

    app = FastAPI(
        title="Project 10 Local Inference API",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    app.state.admission_gate = gate

    def record(reason, requested_model, caller_ref, request_id):
        model_name = (
            requested_model
            if requested_model in PERMISSIONS
            else "unrecognized"
        )
        event = create_event(
            provenance="live-lab",
            source="gateway",
            model=model_name,
            reason=reason,
            caller_ref=caller_ref,
            request_id=request_id,
        )

        try:
            accepted = publish(event) is True
        except Exception:
            accepted = False

        if not accepted:
            raise HTTPException(
                status_code=503,
                detail="Telemetry unavailable",
                headers={"X-Request-ID": request_id},
            )

    def deny(status, detail, reason, requested_model, caller, request_id):
        record(reason, requested_model, caller, request_id)
        headers = {"X-Request-ID": request_id}
        if reason == "concurrency_exceeded":
            headers["Retry-After"] = "1"
        raise HTTPException(
            status_code=status,
            detail=detail,
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request, _exception):
        request_id = str(uuid4())

        try:
            record("invalid_request", "unrecognized", None, request_id)
        except HTTPException:
            return JSONResponse(
                status_code=503,
                content={"detail": "Telemetry unavailable"},
                headers={"X-Request-ID": request_id},
            )

        return JSONResponse(
            status_code=422,
            content={"detail": "Invalid request"},
            headers={"X-Request-ID": request_id},
        )

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "model_version": MODEL_VERSION,
        }

    @app.post("/v1/inference")
    def inference(
        request: InferenceRequest,
        authorization: str | None = Header(default=None),
    ):
        request_id = str(uuid4())

        if authorization is None:
            deny(
                401, "Authentication required",
                "authentication_required",
                request.model, None, request_id,
            )

        scheme, separator, token = authorization.partition(" ")
        if (
            not separator
            or scheme.lower() != "bearer"
            or re.fullmatch(r"[0-9a-f]{64}", token) is None
        ):
            deny(
                401, "Authentication failed",
                "authentication_failed",
                request.model, None, request_id,
            )

        reader = hmac.compare_digest(token, credentials["reader_key"])
        admin = hmac.compare_digest(token, credentials["admin_key"])

        if reader:
            caller = "lab-caller-reader"
            roles = frozenset({"Inference.Reader"})
        elif admin:
            caller = "lab-caller-admin"
            roles = frozenset({"Inference.Admin"})
        else:
            deny(
                401, "Authentication failed",
                "authentication_failed",
                request.model, None, request_id,
            )

        permitted = PERMISSIONS.get(request.model, frozenset())
        if not permitted.intersection(roles):
            deny(
                403, "Model access denied",
                "model_access_denied",
                request.model, caller, request_id,
            )

        if not request.prompt.strip():
            deny(
                422, "Invalid request", "invalid_request",
                request.model, caller, request_id,
            )

        if not gate.try_acquire():
            deny(
                503, "Inference capacity unavailable",
                "concurrency_exceeded",
                request.model, caller, request_id,
            )

        try:
            try:
                blocked = check_access(caller, request.model)
                if type(blocked) is not bool:
                    raise ValueError("Invalid policy result")
            except Exception:
                deny(
                    503, "Access policy unavailable",
                    "response_policy_unavailable",
                    request.model, caller, request_id,
                )

            if blocked:
                deny(
                    403, "Temporary model access block",
                    "containment_enforced",
                    request.model, caller, request_id,
                )

            prediction = classifier.predict(request.prompt)
            record(
                "inference_succeeded",
                request.model,
                caller,
                request_id,
            )

            result = prediction.to_dict()
            result["model"] = request.model

            return JSONResponse(
                content=result,
                headers={"X-Request-ID": request_id},
            )
        finally:
            gate.release()


    return app