"""
Project 10 — Local Loki delivery client.

One delivery attempt per call.
Queue retention and retry scheduling belong to the collector.
"""

import json
from datetime import datetime, timezone
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from src.telemetry.ingestion import CollectedEvent


LOKI_ENDPOINT = "http://127.0.0.1:3100/loki/api/v1/push"
DELIVERY_TIMEOUT_SECONDS = 3


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def collection_timestamp_ns(collected_at: str) -> str:
    timestamp = datetime.fromisoformat(collected_at)

    if (
        timestamp.tzinfo is None
        or timestamp.utcoffset() != timezone.utc.utcoffset(timestamp)
    ):
        raise ValueError("Collection timestamp must use UTC")

    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = timestamp - epoch

    # Integer arithmetic avoids floating-point timestamp rounding.
    nanoseconds = (
        (delta.days * 86400 + delta.seconds) * 1_000_000_000
        + delta.microseconds * 1000
    )
    return str(nanoseconds)


def encode_payload(collected: CollectedEvent) -> bytes:
    payload = {
        "streams": [
            {
                "stream": {
                    "job": "p10-security",
                    "source": collected.event.source,
                    "provenance": collected.event.provenance,
                },
                "values": [
                    [
                        collection_timestamp_ns(collected.collected_at),
                        collected.to_json(),
                    ]
                ],
            }
        ]
    }

    return json.dumps(
        payload,
        separators=(",", ":"),
    ).encode("utf-8")


class LokiClient:
    def __init__(self, opener=None):
        self.opener = (
            opener
            if opener is not None
            else build_opener(ProxyHandler({}), NoRedirects())
        )

    def send(self, collected: CollectedEvent) -> bool:
        request = Request(
            LOKI_ENDPOINT,
            data=encode_payload(collected),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with self.opener.open(
                request,
                timeout=DELIVERY_TIMEOUT_SECONDS,
            ) as response:
                return response.status == 204

        except HTTPError as error:
            error.close()
            return False

        except (URLError, OSError, HTTPException):
            return False