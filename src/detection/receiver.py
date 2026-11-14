"""
Project 10 — Authenticated local finding receiver.

Stores validated findings before returning an acceptance receipt.
Does not send email, perform containment, or establish external delivery.
"""

import hmac
import json
import re
import sqlite3
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from src.detection.store import FindingStore
from src.telemetry.ingestion import reject_constant, unique_object


MAX_FINDING_BYTES = 65536


def load_service_key():
    path = (
        Path.home()
        / ".config/project10/credentials/finding-receiver-key"
    )
    return path.read_text(encoding="utf-8")


def create_app(store=None, service_key=None):
    key = load_service_key() if service_key is None else service_key

    if (
        not isinstance(key, str)
        or re.fullmatch(r"[0-9a-f]{64}", key) is None
    ):
        raise RuntimeError("Invalid receiver credential configuration")

    if store is None:
        store = FindingStore(
            Path.home()
            / ".local/share/project10/monitoring/findings.sqlite3"
        )

    app = FastAPI(
        title="Project 10 Finding Receiver",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    def authorized(request):
        values = request.headers.getlist("authorization")
        if len(values) != 1:
            return False

        scheme, separator, token = values[0].partition(" ")
        if (
            not separator
            or scheme.lower() != "bearer"
            or re.fullmatch(r"[0-9a-f]{64}", token) is None
        ):
            return False

        return hmac.compare_digest(token, key)

    def reply(status, detail):
        return JSONResponse(
            status_code=status,
            content={"detail": detail},
        )

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/findings")
    async def receive(request: Request):
        # Authenticate before reading or parsing the request body.
        if not authorized(request):
            return reply(401, "Service authentication failed")

        if request.headers.get("content-type", "").lower() != (
            "application/json"
        ):
            return reply(415, "Content type must be application/json")

        raw = bytearray()

        try:
            async for chunk in request.stream():
                if len(raw) + len(chunk) > MAX_FINDING_BYTES:
                    return reply(413, "Finding exceeds size limit")
                raw.extend(chunk)

            finding = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            )
        except (ValueError, UnicodeDecodeError, RecursionError):
            return reply(400, "Invalid finding")

        try:
            inserted = await run_in_threadpool(store.put, finding)
        except ValueError:
            return reply(400, "Invalid finding")
        except (RuntimeError, sqlite3.Error):
            return reply(503, "Finding storage unavailable")

        return JSONResponse(
            status_code=201 if inserted else 200,
            content={
                "status": "stored",
                "finding_id": finding["finding_id"],
                "duplicate": not inserted,
            },
        )

    @app.get("/findings/{finding_id}")
    async def get_finding(finding_id: str, request: Request):
        if not authorized(request):
            return reply(401, "Service authentication failed")

        if re.fullmatch(r"[0-9a-f]{64}", finding_id) is None:
            return reply(404, "Finding not found")

        try:
            record = await run_in_threadpool(store.get, finding_id)
        except sqlite3.Error:
            return reply(503, "Finding storage unavailable")

        if record is None:
            return reply(404, "Finding not found")

        return record

    return app