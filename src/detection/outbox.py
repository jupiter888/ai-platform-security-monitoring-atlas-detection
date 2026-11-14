"""
Project 10 — Durable finding outbox.

Pending findings survive reopening and remain until acknowledged.
One pending finding per rule/version/caller/model group.

Delivered records are retained. Capacity exhaustion raises an error;
no pending finding or delivery history is silently evicted.
"""

import json
import sqlite3
from contextlib import closing
from datetime import timedelta, timezone
from pathlib import Path

from src.detection.model_access import utc_timestamp
from src.detection.store import content_identity, validate_finding


def timestamp(value):
    utc_timestamp(value.isoformat())
    return value.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    )


def group_key(finding):
    return json.dumps(
        [
            finding["rule_id"],
            finding["rule_version"],
            finding["caller_ref"],
            finding["model"],
        ],
        separators=(",", ":"),
    )


class FindingOutbox:
    def __init__(self, path, capacity=1000, cooldown_seconds=60):
        if type(capacity) is not int or capacity < 1:
            raise ValueError("Invalid outbox capacity")
        if type(cooldown_seconds) is not int or cooldown_seconds < 1:
            raise ValueError("Invalid outbox cooldown")

        self.path = Path(path)
        self.capacity = capacity
        self.cooldown_seconds = cooldown_seconds

        if self.path.is_symlink():
            raise ValueError("Outbox path must not be a symlink")

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.parent.chmod(0o700)
        self.path.touch(mode=0o600, exist_ok=True)
        self.path.chmod(0o600)

        with closing(sqlite3.connect(self.path, timeout=2)) as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS finding_outbox (
                    finding_id TEXT PRIMARY KEY,
                    group_key TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    queued_at TEXT NOT NULL,
                    delivered_at TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_attempt_at TEXT
                )
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS outbox_group
                ON finding_outbox(group_key)
            """)
            connection.commit()

    def enqueue(self, finding, *, as_of):
        payload = validate_finding(finding)
        queued_at = timestamp(as_of)
        cooldown_start = timestamp(
            as_of - timedelta(seconds=self.cooldown_seconds)
        )
        key = group_key(finding)

        with closing(sqlite3.connect(self.path, timeout=2)) as connection:
            connection.execute("BEGIN IMMEDIATE")

            existing = connection.execute(
                """
                SELECT payload_json
                FROM finding_outbox WHERE finding_id = ?
                """,
                (finding["finding_id"],),
            ).fetchone()

            if existing is not None:
                if content_identity(json.loads(existing[0])) != (
                    content_identity(finding)
                ):
                    raise ValueError("Conflicting finding identifier")
                return "duplicate"

            pending = connection.execute(
                """
                SELECT 1 FROM finding_outbox
                WHERE group_key = ? AND delivered_at IS NULL
                LIMIT 1
                """,
                (key,),
            ).fetchone()

            if pending is not None:
                return "pending"

            recent = connection.execute(
                """
                SELECT 1 FROM finding_outbox
                WHERE group_key = ? AND delivered_at > ?
                LIMIT 1
                """,
                (key, cooldown_start),
            ).fetchone()

            if recent is not None:
                return "suppressed"

            count = connection.execute(
                "SELECT COUNT(*) FROM finding_outbox"
            ).fetchone()[0]

            if count >= self.capacity:
                raise RuntimeError("Outbox capacity reached")

            connection.execute(
                """
                INSERT INTO finding_outbox
                    (finding_id, group_key, payload_json, queued_at)
                VALUES (?, ?, ?, ?)
                """,
                (finding["finding_id"], key, payload, queued_at),
            )
            connection.commit()
            return "queued"

    def pending(self, limit=10):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Invalid pending batch limit")

        with closing(sqlite3.connect(self.path, timeout=2)) as connection:
            rows = connection.execute(
                """
                SELECT payload_json FROM finding_outbox
                WHERE delivered_at IS NULL
                ORDER BY queued_at, finding_id
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [json.loads(row[0]) for row in rows]

    def record_attempt(self, finding_id, *, as_of):
        attempted_at = timestamp(as_of)

        with closing(sqlite3.connect(self.path, timeout=2)) as connection:
            cursor = connection.execute(
                """
                UPDATE finding_outbox
                SET attempts = attempts + 1, last_attempt_at = ?
                WHERE finding_id = ? AND delivered_at IS NULL
                """,
                (attempted_at, finding_id),
            )
            if cursor.rowcount != 1:
                raise LookupError("Pending finding not found")
            connection.commit()

    def mark_delivered(self, finding_id, *, as_of):
        # Call only after validating the receiver's storage receipt.
        delivered_at = timestamp(as_of)

        with closing(sqlite3.connect(self.path, timeout=2)) as connection:
            cursor = connection.execute(
                """
                UPDATE finding_outbox
                SET delivered_at = COALESCE(delivered_at, ?)
                WHERE finding_id = ?
                """,
                (delivered_at, finding_id),
            )
            if cursor.rowcount != 1:
                raise LookupError("Finding not found")
            connection.commit()

    def stats(self):
        with closing(sqlite3.connect(self.path, timeout=2)) as connection:
            total, pending, attempts = connection.execute(
                """
                SELECT
                    COUNT(*),
                    COALESCE(SUM(
                        CASE WHEN delivered_at IS NULL THEN 1 ELSE 0 END
                    ), 0),
                    COALESCE(SUM(attempts), 0)
                FROM finding_outbox
                """
            ).fetchone()

        return {
            "records": total,
            "pending": pending,
            "delivered": total - pending,
            "attempts": attempts,
        }