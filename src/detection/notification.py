"""
Authenticated delivery to the fixed local finding receiver.

One attempt per call. No redirects or environment-derived proxies.
A valid receipt confirms receiver storage, not analyst acknowledgement.
"""

import json
import re
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

from src.detection.store import validate_finding
from src.telemetry.loki import NoRedirects


RECEIVER_ENDPOINT = "http://127.0.0.1:8300/findings"
RECEIVER_TIMEOUT_SECONDS = 3


class ReceiverClient:
    def __init__(self, service_key=None, opener=None):
        if service_key is None:
            path = (
                Path.home()
                / ".config/project10/credentials/finding-receiver-key"
            )
            service_key = path.read_text(encoding="utf-8")

        if (
            not isinstance(service_key, str)
            or re.fullmatch(r"[0-9a-f]{64}", service_key) is None
        ):
            raise RuntimeError("Invalid receiver credential configuration")

        self.service_key = service_key
        self.opener = (
            opener
            if opener is not None
            else build_opener(ProxyHandler({}), NoRedirects())
        )

    def send(self, finding):
        payload = validate_finding(finding).encode("utf-8")

        request = Request(
            RECEIVER_ENDPOINT,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.service_key}",
            },
            method="POST",
        )

        try:
            with self.opener.open(
                request,
                timeout=RECEIVER_TIMEOUT_SECONDS,
            ) as response:
                status = response.status
                raw = response.read(4097)

            if status not in (200, 201) or len(raw) > 4096:
                return None

            receipt = json.loads(raw)

            if (
                not isinstance(receipt, dict)
                or set(receipt) != {
                    "status", "finding_id", "duplicate"
                }
                or receipt["status"] != "stored"
                or receipt["finding_id"] != finding["finding_id"]
                or type(receipt["duplicate"]) is not bool
                or receipt["duplicate"] != (status == 200)
            ):
                return None

            return receipt

        except HTTPError as error:
            error.close()
            return None
        except (URLError, OSError, HTTPException, ValueError):
            return None