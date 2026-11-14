"""
Project 10 — Durable local finding store.

Finding metadata is validated against the immutable rule catalog.
Existing DET-001 records remain compatible.
"""

import hashlib
import json
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from src.detection.catalog import RULES
from src.detection.model_access import utc_timestamp
from src.telemetry.events import CALLER_PATTERN


FINDING_FIELDS = frozenset({
    "finding_id",
    "rule_id",
    "rule_version",
    "severity",
    "classification",
    "caller_ref",
    "model",
    "event_count",
    "threshold",
    "window_seconds",
    "first_seen",
    "last_seen",
    "detected_at",
    "event_ids",
})


def validate_finding(finding):
    if not isinstance(finding, dict) or set(finding) != FINDING_FIELDS:
        raise ValueError("Unexpected finding fields")

    string_fields = FINDING_FIELDS - {
        "event_count", "threshold", "window_seconds", "event_ids",
        "caller_ref"
    }
    for field in string_fields:
        value = finding[field]
        if not isinstance(value, str) or len(value) > 128:
            raise ValueError("Invalid finding field")

    rule = RULES.get(finding["rule_id"])
    if rule is None:
        raise ValueError("Unsupported finding rule")

    if (
        finding["rule_version"] != rule.version
        or finding["severity"] != rule.severity
        or finding["classification"] != rule.classification
    ):
        raise ValueError("Invalid finding metadata")

    if rule.rule_id in {"DET-004", "DET-006"}:
        if (
            finding["caller_ref"] is not None
            or finding["model"] != "not-applicable"
        ):
            raise ValueError("Aggregate finding cannot identify a caller")
    else:
        caller = finding["caller_ref"]
        if (
            not isinstance(caller, str)
            or CALLER_PATTERN.fullmatch(caller) is None
            or finding["model"] not in {
                "research-model", "restricted-model"
            }
        ):
            raise ValueError("Invalid finding target")

    for field in ("event_count", "threshold", "window_seconds"):
        if type(finding[field]) is not int:
            raise ValueError("Invalid finding numeric field")

    ids = finding["event_ids"]
    if (
        not isinstance(ids, list)
        or not rule.threshold <= len(ids) <= 500
        or finding["event_count"] != len(ids)
        or finding["threshold"] != rule.threshold
        or finding["window_seconds"] != rule.window_seconds
    ):
        raise ValueError("Invalid finding evidence")

    for event_id in ids:
        if not isinstance(event_id, str):
            raise ValueError("Invalid evidence identifier")
        try:
            parsed = UUID(event_id)
        except ValueError:
            raise ValueError("Invalid evidence identifier") from None

        if parsed.version != 4 or str(parsed) != event_id:
            raise ValueError("Invalid evidence identifier")

    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate evidence identifier")

    first = utc_timestamp(finding["first_seen"])
    last = utc_timestamp(finding["last_seen"])
    detected = utc_timestamp(finding["detected_at"])

    if not first <= last <= detected:
        raise ValueError("Invalid finding timestamp ordering")

    if (last - first).total_seconds() >= rule.window_seconds:
        raise ValueError("Finding evidence exceeds rule window")

    identity = {
        "rule_id": finding["rule_id"],
        "rule_version": finding["rule_version"],
        "caller_ref": finding["caller_ref"],
        "model": finding["model"],
        "event_ids": ids,
    }
    expected_id = hashlib.sha256(
        json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    if (
        re.fullmatch(r"[0-9a-f]{64}", finding["finding_id"]) is None
        or finding["finding_id"] != expected_id
    ):
        raise ValueError("Finding fingerprint mismatch")

    return json.dumps(
        finding,
        sort_keys=True,
        separators=(",", ":"),
    )


def content_identity(finding):
    content = dict(finding)
    content.pop("detected_at")
    return json.dumps(content, sort_keys=True, separators=(",", ":"))


class FindingStore:
    def __init__(self, path, capacity=1000):
        if type(capacity) is not int or capacity < 1:
            raise ValueError("Invalid store capacity")

        self.path = Path(path)
        self.capacity = capacity

        if self.path.is_symlink():
            raise ValueError("Database path must not be a symlink")

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.parent.chmod(0o700)
        self.path.touch(mode=0o600, exist_ok=True)
        self.path.chmod(0o600)

        with closing(sqlite3.connect(self.path, timeout=2)) as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    identity_json TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    received_at TEXT NOT NULL
                )
            """)
            connection.commit()

    def put(self, finding):
        payload = validate_finding(finding)
        identity = content_identity(finding)
        received_at = datetime.now(timezone.utc).isoformat()

        with closing(sqlite3.connect(self.path, timeout=2)) as connection:
            connection.execute("BEGIN IMMEDIATE")

            existing = connection.execute(
                "SELECT identity_json FROM findings WHERE finding_id = ?",
                (finding["finding_id"],),
            ).fetchone()

            if existing is not None:
                if existing[0] != identity:
                    raise ValueError("Conflicting finding identifier")
                return False

            count = connection.execute(
                "SELECT COUNT(*) FROM findings"
            ).fetchone()[0]

            if count >= self.capacity:
                raise RuntimeError("Finding store capacity reached")

            connection.execute(
                """
                INSERT INTO findings
                    (finding_id, identity_json, payload_json, received_at)
                VALUES (?, ?, ?, ?)
                """,
                (finding["finding_id"], identity, payload, received_at),
            )
            connection.commit()
            return True

    def get(self, finding_id):
        with closing(sqlite3.connect(self.path, timeout=2)) as connection:
            row = connection.execute(
                """
                SELECT payload_json, received_at
                FROM findings WHERE finding_id = ?
                """,
                (finding_id,),
            ).fetchone()

        if row is None:
            return None

        return {
            "finding": json.loads(row[0]),
            "received_at": row[1],
        }

    def count(self):
        with closing(sqlite3.connect(self.path, timeout=2)) as connection:
            return connection.execute(
                "SELECT COUNT(*) FROM findings"
            ).fetchone()[0]