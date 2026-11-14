"""
Project 10 — Scoped, single-execution containment.

Execution, case state, and audit are committed in one SQLite transaction.
Expiry is evaluated when access is checked; no cleanup timer is required.
"""

import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.detection.cases import (
    CONTAINMENT_ACTION,
    CONTAINMENT_POLICY_VERSION,
    CONTAINMENT_SECONDS,
    require_role,
)
from src.detection.model_access import utc_timestamp
from src.telemetry.events import CALLER_PATTERN


def stamp(value):
    utc_timestamp(value.isoformat())
    return value.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    )


def read_block_status(database_path, caller_ref, model, *, as_of=None):
    if (
        not isinstance(caller_ref, str)
        or CALLER_PATTERN.fullmatch(caller_ref) is None
        or model not in {"research-model", "restricted-model"}
    ):
        raise ValueError("Invalid access-check scope")

    path = Path(database_path)
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError("Containment database unavailable")

    at = stamp(
        datetime.now(timezone.utc) if as_of is None else as_of
    )

    with closing(sqlite3.connect(
        path.absolute().as_uri() + "?mode=ro",
        uri=True,
        timeout=2,
    )) as connection:
        row = connection.execute(
            """
            SELECT 1 FROM response_executions
            WHERE caller_ref = ? AND model = ?
              AND started_at <= ? AND expires_at > ?
            LIMIT 1
            """,
            (caller_ref, model, at, at),
        ).fetchone()

    return row is not None


class ContainmentController:
    def __init__(self, ledger):
        self.ledger = ledger
        self.path = ledger.path

        with closing(sqlite3.connect(self.path, timeout=2)) as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS response_executions (
                    case_id TEXT PRIMARY KEY,
                    caller_ref TEXT NOT NULL,
                    model TEXT NOT NULL,
                    action TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    duration_seconds INTEGER NOT NULL,
                    executed_by TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
            """)
            connection.commit()

    def _receipt(self, row, at, duplicate):
        return {
            **dict(row),
            "status": "executed",
            "duplicate": duplicate,
            "active": (
                utc_timestamp(row["started_at"])
                <= at
                < utc_timestamp(row["expires_at"])
            ),
        }

    def execute(self, case_id, actor, *, as_of=None):
        require_role(actor, "responder")
        current = datetime.now(timezone.utc) if as_of is None else as_of
        started_at = stamp(current)
        expires_at = stamp(
            current + timedelta(seconds=CONTAINMENT_SECONDS)
        )

        with closing(sqlite3.connect(self.path, timeout=2)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN IMMEDIATE")

            existing = connection.execute(
                "SELECT * FROM response_executions WHERE case_id = ?",
                (case_id,),
            ).fetchone()

            if existing is not None:
                if existing["executed_by"] != actor.subject:
                    raise PermissionError("Execution principal mismatch")
                return self._receipt(existing, current, True)

            case = connection.execute(
                "SELECT * FROM cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()

            if case is None:
                raise LookupError("Case not found")

            if (
                case["state"] != "containment_approved"
                or case["requester"] is None
                or case["approver"] is None
                or case["requester"] == case["approver"]
                or case["containment_action"] != CONTAINMENT_ACTION
                or case["containment_seconds"] != CONTAINMENT_SECONDS
                or case["containment_policy_version"]
                != CONTAINMENT_POLICY_VERSION
                or CALLER_PATTERN.fullmatch(case["caller_ref"]) is None
                or case["model"] not in {
                    "research-model", "restricted-model"
                }
            ):
                raise ValueError("Case is not eligible for execution")

            if actor.subject in {
                case["opened_by"], case["requester"], case["approver"]
            }:
                raise PermissionError("Independent responder required")

            active = connection.execute(
                """
                SELECT 1 FROM response_executions
                WHERE caller_ref = ? AND model = ?
                  AND started_at <= ? AND expires_at > ?
                LIMIT 1
                """,
                (
                    case["caller_ref"], case["model"],
                    started_at, started_at,
                ),
            ).fetchone()

            if active is not None:
                raise ValueError("Scope already has active containment")

            connection.execute(
                """
                INSERT INTO response_executions
                    (case_id, caller_ref, model, action, policy_version,
                     duration_seconds, executed_by, started_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id, case["caller_ref"], case["model"],
                    CONTAINMENT_ACTION, CONTAINMENT_POLICY_VERSION,
                    CONTAINMENT_SECONDS, actor.subject,
                    started_at, expires_at,
                ),
            )
            connection.execute(
                """
                UPDATE cases
                SET state = ?, updated_at = ?
                WHERE case_id = ?
                """,
                ("containment_executed", started_at, case_id),
            )
            self.ledger._audit(
                connection, case_id, actor,
                "containment_executed",
                "containment_executed",
                "controlled_exercise",
                started_at,
            )
            connection.commit()

            execution = connection.execute(
                "SELECT * FROM response_executions WHERE case_id = ?",
                (case_id,),
            ).fetchone()

            return self._receipt(execution, current, False)