"""
Verify a stored finding through the authenticated receiver API.

Does not print credentials or modify the finding.
A duplicate delivery must preserve the original stored record.
"""

import argparse
import json
import re
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from src.detection.store import validate_finding
from src.telemetry.loki import NoRedirects


def request_json(opener, request):
    try:
        response = opener.open(request, timeout=5)
    except HTTPError as error:
        response = error

    with response:
        raw = response.read(131073)
        if len(raw) > 131072:
            raise RuntimeError("Response exceeds validation limit")
        return response.code, json.loads(raw)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("finding_id")
    args = parser.parse_args()

    if re.fullmatch(r"[0-9a-f]{64}", args.finding_id) is None:
        raise SystemExit("Invalid finding identifier")

    path = (
        Path.home()
        / ".config/project10/credentials/finding-receiver-key"
    )
    key = path.read_text(encoding="utf-8")

    opener = build_opener(ProxyHandler({}), NoRedirects())
    endpoint = (
        "http://127.0.0.1:8300/findings/"
        + args.finding_id
    )

    status, _ = request_json(opener, Request(endpoint))
    if status != 401:
        raise RuntimeError("Unauthenticated retrieval was not rejected")
    print("PASS: unauthenticated finding retrieval rejected")

    headers = {"Authorization": f"Bearer {key}"}
    status, original = request_json(
        opener,
        Request(endpoint, headers=headers),
    )

    if status != 200 or set(original) != {"finding", "received_at"}:
        raise RuntimeError("Authenticated finding retrieval failed")

    finding = original["finding"]
    validate_finding(finding)
    if finding["finding_id"] != args.finding_id:
        raise RuntimeError("Retrieved finding identifier mismatch")

    print("PASS: authenticated retrieval returns the validated finding")

    status, receipt = request_json(
        opener,
        Request(
            "http://127.0.0.1:8300/findings",
            data=json.dumps(finding).encode("utf-8"),
            headers={
                **headers,
                "Content-Type": "application/json",
            },
            method="POST",
        ),
    )

    if status != 200 or receipt != {
        "status": "stored",
        "finding_id": args.finding_id,
        "duplicate": True,
    }:
        raise RuntimeError("Duplicate-delivery receipt contract failed")

    print("PASS: repeat delivery returns an existing-record receipt")

    status, repeated = request_json(
        opener,
        Request(endpoint, headers=headers),
    )
    if status != 200 or repeated != original:
        raise RuntimeError("Duplicate delivery changed the stored record")

    print("PASS: original finding and receipt timestamp remain unchanged")
    print("Finding receipt validation: 4/4 passed")

if __name__ == "__main__":
    main()