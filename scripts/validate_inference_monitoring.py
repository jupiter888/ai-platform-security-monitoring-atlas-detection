"""
Project 10 — Actual inference requests and correlated Loki events.

Uses private local credentials without printing or persisting them.
This validates visibility, not detection-rule effectiveness.
"""

import json
import math
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)
from uuid import UUID


INPUT_CANARY = "P10-SYNTHETIC-INPUT-CANARY"
PROMPT = f"{INPUT_CANARY}. A telescope observes distant planets."


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_json(opener, request):
    try:
        response = opener.open(request, timeout=10)
    except HTTPError as error:
        response = error

    with response:
        raw = response.read(524289)
        if len(raw) > 524288:
            raise RuntimeError("Validation response too large")

        return (
            response.code,
            dict(response.headers),
            json.loads(raw),
        )


def main():
    credential_path = (
        Path.home()
        / ".config/project10/credentials/inference-clients.json"
    )
    credentials = json.loads(
        credential_path.read_text(encoding="utf-8")
    )
    reader = credentials["reader_key"]
    admin = credentials["admin_key"]
    invalid = next(
        character * 64
        for character in "012"
        if character * 64 not in (reader, admin)
    )

    opener = build_opener(ProxyHandler({}), NoRedirects())
    start_ns = time.time_ns() - 5_000_000_000

    status, _, health = request_json(
        opener,
        Request("http://127.0.0.1:8200/health"),
    )
    if status != 200:
        raise RuntimeError("Inference API is not healthy")

    model_version = health["model_version"]

    cases = [
        (
            "Reader inference",
            reader,
            {"model": "research-model", "prompt": PROMPT},
            200,
            "inference_succeeded",
            "research-model",
            "lab-caller-reader",
        ),
        (
            "Reader restricted-model denial",
            reader,
            {"model": "restricted-model", "prompt": PROMPT},
            403,
            "model_access_denied",
            "restricted-model",
            "lab-caller-reader",
        ),
        (
            "Admin restricted-model inference",
            admin,
            {"model": "restricted-model", "prompt": PROMPT},
            200,
            "inference_succeeded",
            "restricted-model",
            "lab-caller-admin",
        ),
        (
            "Missing credential",
            None,
            {"model": "research-model", "prompt": PROMPT},
            401,
            "authentication_required",
            "research-model",
            None,
        ),
        (
            "Invalid credential",
            invalid,
            {"model": "research-model", "prompt": PROMPT},
            401,
            "authentication_failed",
            "research-model",
            None,
        ),
        (
            "Invalid request schema",
            reader,
            {"prompt": PROMPT},
            422,
            "invalid_request",
            "unrecognized",
            None,
        ),
    ]

    expected = {}

    for label, key, body, wanted_status, reason, model, caller in cases:
        headers = {"Content-Type": "application/json"}
        if key is not None:
            headers["Authorization"] = f"Bearer {key}"

        status, response_headers, payload = request_json(
            opener,
            Request(
                "http://127.0.0.1:8200/v1/inference",
                data=json.dumps(body).encode("utf-8"),
                headers=headers,
                method="POST",
            ),
        )

        if status != wanted_status:
            raise RuntimeError(
                f"{label}: HTTP {status}; expected {wanted_status}"
            )

        request_id = next(
            (
                value
                for name, value in response_headers.items()
                if name.lower() == "x-request-id"
            ),
            "",
        )
        parsed = UUID(request_id)
        if parsed.version != 4 or str(parsed) != request_id:
            raise RuntimeError("Invalid server correlation identifier")
        if request_id in expected:
            raise RuntimeError("Repeated request correlation identifier")

        if status == 200:
            if set(payload) != {
                "model", "model_version", "label", "score"
            }:
                raise RuntimeError("Unexpected prediction contract")
            if (
                payload["model"] != model
                or payload["model_version"] != model_version
                or payload["label"] not in {
                    "astronomy", "botany", "geology"
                }
                or type(payload["score"]) not in (int, float)
                or not math.isfinite(payload["score"])
                or not 0 <= payload["score"] <= 1
            ):
                raise RuntimeError("Invalid prediction values")
        else:
            if (
                set(payload) != {"detail"}
                or not isinstance(payload["detail"], str)
            ):
                raise RuntimeError("Unexpected denial contract")

        if INPUT_CANARY in json.dumps(payload):
            raise RuntimeError("Submitted input reflected in response")

        expected[request_id] = {
            "label": label,
            "reason": reason,
            "model": model,
            "caller_ref": caller,
        }
        print(f"PASS: {label} — HTTP {status}")

    identifiers = "|".join(expected)
    expression = (
        '{job="p10-security",source="gateway",provenance="live-lab"}'
        ' | json'
        f' | request_id=~"{identifiers}"'
    )

    records = []
    deadline = time.monotonic() + 30

    while time.monotonic() < deadline:
        parameters = urlencode({
            "query": expression,
            "start": str(start_ns),
            "end": str(time.time_ns()),
            "direction": "forward",
            "limit": "100",
        })
        status, _, result = request_json(
            opener,
            Request(
                "http://127.0.0.1:3100/loki/api/v1/query_range?"
                + parameters
            ),
        )
        if status != 200 or result.get("status") != "success":
            raise RuntimeError("Loki query failed")

        records = [
            json.loads(line)
            for stream in result["data"]["result"]
            for _, line in stream["values"]
        ]
        observed = {record.get("request_id") for record in records}

        if set(expected).issubset(observed):
            break

        time.sleep(1)
    else:
        raise RuntimeError("Some request events were not queryable in time")

    for record in records:
        request_id = record.get("request_id")
        if request_id not in expected:
            raise RuntimeError("Unexpected correlated event")

        wanted = expected[request_id]
        for field in ("reason", "model", "caller_ref"):
            if record.get(field) != wanted[field]:
                raise RuntimeError("Correlated event content mismatch")

        if (
            record.get("provenance") != "live-lab"
            or record.get("source") != "gateway"
        ):
            raise RuntimeError("Unexpected event source or provenance")

        serialized = json.dumps(record)
        if any(
            canary in serialized
            for canary in (INPUT_CANARY, reader, admin, invalid)
        ):
            raise RuntimeError("Sensitive-data canary found in event")

    print("PASS: all six requests have matching live-lab events in Loki")
    print("PASS: queried events exclude input and credential canaries")
    print(f"Matching log records: {len(records)}")
    print("Inference monitoring validation: 8/8 passed")
    print("Scope: actual local API activity; no detection rule evaluated")

if __name__ == "__main__":
    main()