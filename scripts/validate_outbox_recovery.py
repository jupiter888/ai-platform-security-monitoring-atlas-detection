"""
Verify recovery of the finding saved in the outage checkpoint.

Reads the outbox without modifying it and retrieves the receiver record
through its authenticated API. Credentials are never printed.
"""

import json
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path
from urllib.request import ProxyHandler, Request, build_opener

from src.detection.store import validate_finding
from src.telemetry.loki import NoRedirects


def main():
    checkpoint = json.loads(
        Path(
            "evidence/public/outbox-pending-checkpoint.json"
        ).read_text(encoding="utf-8")
    )
    expected = checkpoint["finding"]
    validate_finding(expected)
    finding_id = expected["finding_id"]

    if checkpoint["outbox_stats"]["pending"] != 1:
        raise RuntimeError("Checkpoint does not show the pending finding")
    print("PASS: checkpoint records the pending finding")

    database = (
        Path.home()
        / ".local/share/project10/monitoring/outbox.sqlite3"
    )
    with closing(sqlite3.connect(
        database.as_uri() + "?mode=ro",
        uri=True,
    )) as connection:
        row = connection.execute(
            """
            SELECT payload_json, delivered_at, attempts
            FROM finding_outbox WHERE finding_id = ?
            """,
            (finding_id,),
        ).fetchone()

    if (
        row is None
        or row[1] is None
        or json.loads(row[0]) != expected
    ):
        raise RuntimeError("Original finding is not marked delivered")

    print("PASS: original persisted finding is acknowledged as delivered")

    delivered_at = datetime.fromisoformat(row[1])
    last_seen = datetime.fromisoformat(expected["last_seen"])
    checkpoint_at = datetime.fromisoformat(checkpoint["checkpoint_at"])

    if (
        (delivered_at - last_seen).total_seconds() <= 60
        or delivered_at <= checkpoint_at
    ):
        raise RuntimeError("Delivery was not after source-window expiration")

    print("PASS: delivery occurred after the source-event window expired")

    key_path = (
        Path.home()
        / ".config/project10/credentials/finding-receiver-key"
    )
    key = key_path.read_text(encoding="utf-8")
    opener = build_opener(ProxyHandler({}), NoRedirects())

    request = Request(
        "http://127.0.0.1:8300/findings/" + finding_id,
        headers={"Authorization": f"Bearer {key}"},
    )
    with opener.open(request, timeout=5) as response:
        raw = response.read(131073)
        if response.status != 200 or len(raw) > 131072:
            raise RuntimeError("Receiver retrieval failed")
        stored = json.loads(raw)

    if stored.get("finding") != expected:
        raise RuntimeError("Receiver finding differs from queued evidence")

    print("PASS: authenticated receiver record matches the original finding")
    print(f"Persisted delivery attempts: {row[2]}")
    print("Outbox recovery validation: 4/4 passed")
    print("Scope: queued-finding recovery; not offline detection coverage")

if __name__ == "__main__":
    main()