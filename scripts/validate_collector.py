"""
Project 10 — Live local collector validation.

Uses synthetic events and a fixed loopback destination.
Does not exercise actual gateway authentication.
"""

import json
from urllib.error import HTTPError
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from src.telemetry.events import create_event
from src.telemetry.producer_credentials import load_producer_key


ENDPOINT = "http://127.0.0.1:8100/events"


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def submit(opener, raw):
    request = Request(
        ENDPOINT,
        data=raw,
        headers={
                "Content-Type": "application/json",
                "Authorization": (
                    "Bearer " + load_producer_key("fixture")
                ),
            },
        method="POST",
    )

    try:
        response = opener.open(request, timeout=5)
    except HTTPError as response:
        with response:
            return response.code, response.read(4096)

    with response:
        return response.status, response.read(4096)


def main():
    opener = build_opener(ProxyHandler({}), NoRedirects())
    events = []

    for reason, caller in (
        ("inference_succeeded", "lab-caller-reader"),
        ("authentication_failed", None),
        ("model_access_denied", "lab-caller-reader"),
    ):
        event = create_event(
            provenance="synthetic",
            source="gateway",
            model="research-model",
            reason=reason,
            caller_ref=caller,
        )
        raw = event.to_json().encode("utf-8")
        status, _ = submit(opener, raw)

        if status != 202:
            raise RuntimeError(
                f"Expected event acceptance; received HTTP {status}"
            )

        events.append(raw)
        print(f"PASS: {reason} event buffered")

    status, _ = submit(opener, events[0])
    if status != 409:
        raise RuntimeError(
            f"Expected duplicate rejection; received HTTP {status}"
        )
    print("PASS: duplicate event rejected")

    canary = "synthetic-secret-canary"
    status, body = submit(
        opener,
        json.dumps({"token": canary}).encode("utf-8"),
    )
    if status != 400 or canary.encode("utf-8") in body:
        raise RuntimeError("Invalid-event rejection contract failed")
    print("PASS: invalid event rejected without reflecting input")

    print("Live collector validation: 5/5 passed")
    print("Provenance: synthetic; no gateway attack was executed")

if __name__ == "__main__":
    main()