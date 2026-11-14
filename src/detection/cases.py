"""
Project 10 — Persistent case disposition and scoped approval.

Actors must come from the trusted authentication boundary.
Approval records a specific action, target, duration, and policy version.
This module does not execute containment.
"""

import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


CONTAINMENT_ACTION = "temporary_model_access_block"
CONTAINMENT_SECONDS = 60
CONTAINMENT_POLICY_VERSION = "1.0"


@dataclass(frozen=True)
class Actor:
    subject: str
    role: str

    def __post_init__(self):
        if (
            not isinstance(self.subject, str)
            or re.fullmatch(
                r"lab-operator-[a-z0-9]{1,24}", self.subject
            ) is None
            or self.role not in {"analyst", "approver", "responder"}
        ):
            raise ValueError("Invalid operator identity")


def require_role(actor, role):
    if not isinstance(actor, Actor) or actor.role != role:
        raise PermissionError("Operator role denied")


class CaseLedger:
    def __init__(self, path, finding_store, capacity=1000):
        if type(capacity) is not int or capacity < 1:
            raise ValueError("Invalid case capacity")

        self.path = Path(path)
        self.finding_store = finding_store
        self.capacity = capacity

        if self.path.is_symlink():
            raise ValueError("Case database must not be a symlink")

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.parent.chmod(0o700)
        self.path.touch(mode=0o600, exist_ok=True)
        self.path.chmod(0o600)

        with closing(sqlite3.connect(self.path, timeout=2)) as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL UNIQUE,
                    caller_ref TEXT NOT NULL,
                    model TEXT NOT NULL,
                    state TEXT NOT NULL,
                    opened_by TEXT NOT NULL,
                    requester TEXT,
                    approver TEXT,
                    opened_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    containment_action TEXT,
                    containment_seconds INTEGER,
                    containment_policy_version TEXT
                )
            """)

            columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(cases)")
            }
            migrations = (
                (
                    "containment_action",
                    "ALTER TABLE cases ADD COLUMN containment_action TEXT",
                ),
                (
                    "containment_seconds",
                    "ALTER TABLE cases ADD COLUMN containment_seconds INTEGER",
                ),
                (
                    "containment_policy_version",
                    "ALTER TABLE cases ADD COLUMN containment_policy_version TEXT",
                ),
            )
            for name, statement in migrations:
                if name not in columns:
                    connection.execute(statement)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS case_audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    new_state TEXT NOT NULL,
                    reason TEXT NOT NULL
                )
            """)
            connection.commit()

    def _audit(self, connection, case_id, actor, action, state, reason, at):
        connection.execute(
            """
            INSERT INTO case_audit
                (case_id, timestamp, actor, role, action, new_state, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id, at, actor.subject, actor.role,
                action, state, reason,
            ),
        )

    def open_case(self, finding_id, actor):
        require_role(actor, "analyst")

        stored = self.finding_store.get(finding_id)
        if stored is None:
            raise LookupError("Stored finding not found")

        finding = stored["finding"]
        if (
            finding.get("caller_ref") is None
            or finding.get("model") not in {
                "research-model", "restricted-model"
            }
        ):
            raise ValueError(
                "Finding has no supported caller-specific response target"
            )
        case_id = str(uuid4())
        at = datetime.now(timezone.utc).isoformat()

        with closing(sqlite3.connect(self.path, timeout=2)) as connection:
            connection.execute("BEGIN IMMEDIATE")

            existing = connection.execute(
                "SELECT 1 FROM cases WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
            if existing is not None:
                raise ValueError("Finding already has a case")

            count = connection.execute(
                "SELECT COUNT(*) FROM cases"
            ).fetchone()[0]
            if count >= self.capacity:
                raise RuntimeError("Case capacity reached")

            connection.execute(
                """
                INSERT INTO cases
                    (case_id, finding_id, caller_ref, model, state,
                     opened_by, opened_at, updated_at,
                     containment_action, containment_seconds,
                     containment_policy_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id, finding_id,
                    finding["caller_ref"], finding["model"],
                    "open", actor.subject, at, at,
                    CONTAINMENT_ACTION,
                    CONTAINMENT_SECONDS,
                    CONTAINMENT_POLICY_VERSION,
                ),
            )
            self._audit(
                connection, case_id, actor,
                "case_opened", "open", "finding_review", at,
            )
            connection.commit()

        return self.get(case_id)

    def _transition(
        self, case_id, actor, *,
        expected_state, new_state, action, reason,
        set_requester=False, set_approver=False,
    ):
        at = datetime.now(timezone.utc).isoformat()

        with closing(sqlite3.connect(self.path, timeout=2)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN IMMEDIATE")

            row = connection.execute(
                "SELECT * FROM cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
            if row is None:
                raise LookupError("Case not found")
            if row["state"] != expected_state:
                raise ValueError("Case transition denied")

            if set_requester or set_approver:
                if (
                    row["containment_action"] != CONTAINMENT_ACTION
                    or row["containment_seconds"] != CONTAINMENT_SECONDS
                    or row["containment_policy_version"]
                    != CONTAINMENT_POLICY_VERSION
                ):
                    raise ValueError("Unsupported containment scope")

            if set_approver and actor.subject in {
                row["opened_by"], row["requester"]
            }:
                raise PermissionError("Independent approval required")

            requester = (
                actor.subject if set_requester else row["requester"]
            )
            approver = (
                actor.subject if set_approver else row["approver"]
            )

            connection.execute(
                """
                UPDATE cases
                SET state = ?, requester = ?, approver = ?, updated_at = ?
                WHERE case_id = ?
                """,
                (new_state, requester, approver, at, case_id),
            )
            self._audit(
                connection, case_id, actor,
                action, new_state, reason, at,
            )
            connection.commit()

        return self.get(case_id)

    def close_benign(self, case_id, actor):
        require_role(actor, "analyst")
        return self._transition(
            case_id, actor,
            expected_state="open",
            new_state="closed_benign",
            action="case_closed_benign",
            reason="approved_activity",
        )

    def request_containment(self, case_id, actor):
        require_role(actor, "analyst")
        return self._transition(
            case_id, actor,
            expected_state="open",
            new_state="containment_requested",
            action="containment_requested",
            reason="controlled_exercise",
            set_requester=True,
        )

    def approve_containment(self, case_id, actor):
        require_role(actor, "approver")
        return self._transition(
            case_id, actor,
            expected_state="containment_requested",
            new_state="containment_approved",
            action="containment_approved",
            reason="controlled_exercise",
            set_approver=True,
        )

    def get(self, case_id):
        with closing(sqlite3.connect(self.path, timeout=2)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN")

            row = connection.execute(
                "SELECT * FROM cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
            if row is None:
                return None

            audit = connection.execute(
                """
                SELECT sequence, timestamp, actor, role,
                       action, new_state, reason
                FROM case_audit WHERE case_id = ?
                ORDER BY sequence
                """,
                (case_id,),
            ).fetchall()

            result = dict(row)
            result["audit"] = [dict(item) for item in audit]
            return result