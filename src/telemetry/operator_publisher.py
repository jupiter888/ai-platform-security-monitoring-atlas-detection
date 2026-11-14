"""Bounded operator-event publication to the local collector."""

import json
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

from src.telemetry.loki import NoRedirects
from src.telemetry.operator_events import OperatorEvent
from src.telemetry.producer_credentials import load_producer_key


COLLECTOR_ENDPOINT = "http://127.0.0.1:8100/events"


class OperatorPublisher:
    def __init__(self, opener=None, producer_key=None):
        self.producer_key = (
            load_producer_key("operator")
            if producer_key is None else producer_key
        )
        self.opener = (
            build_opener(ProxyHandler({}), NoRedirects())
            if opener is None else opener
        )

    def send(self, event):
        if not isinstance(event, OperatorEvent):
            return False

        request = Request(
            COLLECTOR_ENDPOINT,
            data=event.to_json().encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.producer_key}",
            },
            method="POST",
        )

        try:
            with self.opener.open(request, timeout=2) as response:
                raw = response.read(4097)
                if response.status != 202 or len(raw) > 4096:
                    return False
                receipt = json.loads(raw.decode("utf-8"))
                return receipt == {"detail": "Event buffered"}
        except HTTPError as error:
            error.close()
            return False
        except (
            URLError,
            OSError,
            HTTPException,
            ValueError,
            UnicodeDecodeError,
            RecursionError,
        ):
            return False