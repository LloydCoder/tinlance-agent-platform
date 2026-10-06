"""Durable execution journal contracts.

The journal persists execution identity, lifecycle state, and terminal results without
persisting request input. External side effects are treated as at-least-once and an
execution that may have crossed the side-effect boundary is never blindly replayed.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol
from uuid import UUID

if TYPE_CHECKING:
    from .service import ExecutionResult


class JournalState(StrEnum):
    REQUESTED = "requested"
    WAITING_APPROVAL = "waiting_approval"
    AUTHORIZED = "authorized"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    DENIED = "denied"
    BUDGET_EXCEEDED = "budget_exceeded"
    OUTCOME_UNKNOWN = "outcome_unknown"


TERMINAL_STATES = frozenset(
    {
        JournalState.COMPLETED,
        JournalState.FAILED,
        JournalState.TIMED_OUT,
        JournalState.CANCELLED,
        JournalState.DENIED,
        JournalState.BUDGET_EXCEEDED,
        JournalState.OUTCOME_UNKNOWN,
    }
)


@dataclass(frozen=True, slots=True)
class JournalRecord:
    execution_id: UUID
    tenant_id: str
    principal_id: str
    agent_id: UUID
    run_id: UUID
    request_id: str
    idempotency_key: str
    fingerprint: str
    state: JournalState
    side_effect_started: bool
    policy_decision_id: str
    approval_id: UUID | None
    trace_id: str | None
    result_json: str | None
    updated_at: datetime


class ExecutionJournal(Protocol):
    def create(self, record: JournalRecord) -> bool: ...
    def get(self, tenant_id: str, execution_id: UUID) -> JournalRecord | None: ...
    def get_by_idempotency(self, tenant_id: str, key: str) -> JournalRecord | None: ...
    def transition(
        self,
        tenant_id: str,
        execution_id: UUID,
        state: JournalState,
        *,
        side_effect_started: bool | None = None,
        policy_decision_id: str | None = None,
        result_json: str | None = None,
    ) -> JournalRecord: ...

    def list_recovery_candidates(
        self, tenant_id: str | None = None
    ) -> tuple[JournalRecord, ...]: ...


class SQLiteExecutionJournal:
    """Crash-safe single-host journal.

    SQLite is a reference adapter for development and single-host execution. Production
    deployments should provide the same protocol over the Platform's durable PostgreSQL
    boundary. WAL + synchronous=FULL is deliberate: acknowledged journal transitions
    must survive application crashes and maximize power-loss durability.
    """

    def __init__(self, path: str) -> None:
        if not path.strip():
            raise ValueError("journal database path is required")
        self.path = path
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS governed_execution_journal (
                    execution_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    state TEXT NOT NULL,
                    side_effect_started INTEGER NOT NULL DEFAULT 0,
                    policy_decision_id TEXT NOT NULL DEFAULT '',
                    approval_id TEXT,
                    trace_id TEXT,
                    result_json TEXT,
                    updated_at TEXT NOT NULL,
                    UNIQUE (tenant_id, idempotency_key)
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_execution_journal_recovery
                ON governed_execution_journal (tenant_id, state, side_effect_started)
                """
            )
            connection.commit()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    @staticmethod
    def _decode(row: sqlite3.Row | None) -> JournalRecord | None:
        if row is None:
            return None
        return JournalRecord(
            UUID(row["execution_id"]),
            row["tenant_id"],
            row["principal_id"],
            UUID(row["agent_id"]),
            UUID(row["run_id"]),
            row["request_id"],
            row["idempotency_key"],
            row["fingerprint"],
            JournalState(row["state"]),
            bool(row["side_effect_started"]),
            row["policy_decision_id"],
            UUID(row["approval_id"]) if row["approval_id"] else None,
            row["trace_id"],
            row["result_json"],
            datetime.fromisoformat(row["updated_at"]),
        )

    def create(self, record: JournalRecord) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO governed_execution_journal (
                    execution_id, tenant_id, principal_id, agent_id, run_id,
                    request_id, idempotency_key, fingerprint, state,
                    side_effect_started, policy_decision_id, approval_id,
                    trace_id, result_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(record.execution_id),
                    record.tenant_id,
                    record.principal_id,
                    str(record.agent_id),
                    str(record.run_id),
                    record.request_id,
                    record.idempotency_key,
                    record.fingerprint,
                    record.state.value,
                    int(record.side_effect_started),
                    record.policy_decision_id,
                    str(record.approval_id) if record.approval_id else None,
                    record.trace_id,
                    record.result_json,
                    record.updated_at.isoformat(),
                ),
            )
            connection.commit()
            return cursor.rowcount == 1

    def get(self, tenant_id: str, execution_id: UUID) -> JournalRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM governed_execution_journal
                WHERE tenant_id = ? AND execution_id = ?
                """,
                (tenant_id, str(execution_id)),
            ).fetchone()
        return self._decode(row)

    def get_by_idempotency(self, tenant_id: str, key: str) -> JournalRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM governed_execution_journal
                WHERE tenant_id = ? AND idempotency_key = ?
                """,
                (tenant_id, key),
            ).fetchone()
        return self._decode(row)

    def transition(
        self,
        tenant_id: str,
        execution_id: UUID,
        state: JournalState,
        *,
        side_effect_started: bool | None = None,
        policy_decision_id: str | None = None,
        result_json: str | None = None,
    ) -> JournalRecord:
        with self._connect() as connection:
            current = connection.execute(
                """
                SELECT * FROM governed_execution_journal
                WHERE tenant_id = ? AND execution_id = ?
                """,
                (tenant_id, str(execution_id)),
            ).fetchone()
            if current is None:
                raise KeyError("execution is not present in durable journal")
            current_record = self._decode(current)
            assert current_record is not None
            next_side_effect = (
                current_record.side_effect_started
                if side_effect_started is None
                else side_effect_started
            )
            if current_record.side_effect_started and not next_side_effect:
                raise ValueError("side-effect marker cannot be cleared")
            next_policy = (
                current_record.policy_decision_id
                if policy_decision_id is None
                else policy_decision_id
            )
            next_result = current_record.result_json if result_json is None else result_json
            updated_at = datetime.now(UTC)
            connection.execute(
                """
                UPDATE governed_execution_journal
                SET state = ?, side_effect_started = ?, policy_decision_id = ?,
                    result_json = ?, updated_at = ?
                WHERE tenant_id = ? AND execution_id = ?
                """,
                (
                    state.value,
                    int(next_side_effect),
                    next_policy,
                    next_result,
                    updated_at.isoformat(),
                    tenant_id,
                    str(execution_id),
                ),
            )
            connection.commit()
            row = connection.execute(
                """
                SELECT * FROM governed_execution_journal
                WHERE tenant_id = ? AND execution_id = ?
                """,
                (tenant_id, str(execution_id)),
            ).fetchone()
        record = self._decode(row)
        if record is None:
            raise RuntimeError("durable journal transition disappeared")
        return record

    def list_recovery_candidates(self, tenant_id: str | None = None) -> tuple[JournalRecord, ...]:
        states = tuple(state.value for state in JournalState if state not in TERMINAL_STATES)
        placeholders = ",".join("?" for _ in states)
        query = (
            "SELECT * FROM governed_execution_journal "
            f"WHERE state IN ({placeholders}) "
            "ORDER BY updated_at ASC"
        )
        parameters: list[object] = list(states)
        if tenant_id is not None:
            query = query.replace(
                "ORDER BY updated_at ASC",
                "AND tenant_id = ? ORDER BY updated_at ASC",
            )
            parameters.append(tenant_id)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return tuple(record for row in rows if (record := self._decode(row)) is not None)


def encode_result(result: ExecutionResult) -> str:
    """Serialize an ExecutionResult without coupling the journal to execution package imports."""
    payload = {
        "execution_id": str(result.execution_id),
        "state": result.state.value,
        "output": result.output,
        "evidence_ids": [str(item) for item in result.evidence_ids],
        "audit_event_ids": [str(item) for item in result.audit_event_ids],
        "error_code": result.error_code.value if result.error_code else None,
        "retryable": result.retryable,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))
