from __future__ import annotations

import json
from datetime import UTC, datetime
from tempfile import TemporaryDirectory
from uuid import UUID, uuid4

import pytest

from tinlance_agent_platform_execution import (
    JournalRecord,
    JournalState,
    SQLiteExecutionJournal,
)

TENANT = "tenant-durable"
EXECUTION_ID = UUID("00000000-0000-0000-0000-000000000301")
AGENT_ID = UUID("00000000-0000-0000-0000-000000000302")
RUN_ID = UUID("00000000-0000-0000-0000-000000000303")


def record(*, execution_id: UUID = EXECUTION_ID, key: str = "idem-1") -> JournalRecord:
    return JournalRecord(
        execution_id,
        TENANT,
        "subject-durable",
        AGENT_ID,
        RUN_ID,
        "request-durable",
        key,
        "fingerprint-durable",
        JournalState.REQUESTED,
        False,
        "",
        None,
        "trace-durable",
        None,
        datetime.now(UTC),
    )

def test_journal_survives_reopen_and_recovers_inflight_work() -> None:
    with TemporaryDirectory() as directory:
        path = f"{directory}/journal.sqlite"
        first = SQLiteExecutionJournal(path)
        assert first.create(record())
        first.transition(TENANT, EXECUTION_ID, JournalState.RUNNING, side_effect_started=True)
        reopened = SQLiteExecutionJournal(path)
        recovered = reopened.get(TENANT, EXECUTION_ID)
        assert recovered is not None
        assert recovered.state is JournalState.RUNNING
        assert recovered.side_effect_started is True
        assert [item.execution_id for item in reopened.list_recovery_candidates(TENANT)] == [
            EXECUTION_ID
        ]

def test_terminal_result_is_durable_and_replayable() -> None:
    with TemporaryDirectory() as directory:
        path = f"{directory}/journal.sqlite"
        journal = SQLiteExecutionJournal(path)
        assert journal.create(record())
        result = {
            "execution_id": str(EXECUTION_ID),
            "state": "completed",
            "output": "safe result",
            "evidence_ids": [str(uuid4())],
            "audit_event_ids": [str(uuid4())],
            "error_code": None,
            "retryable": False,
        }
        journal.transition(
            TENANT,
            EXECUTION_ID,
            JournalState.COMPLETED,
            side_effect_started=True,
            result_json=json.dumps(result, sort_keys=True),
        )
        reopened = SQLiteExecutionJournal(path)
        recovered = reopened.get_by_idempotency(TENANT, "idem-1")
        assert recovered is not None
        assert recovered.state is JournalState.COMPLETED
        assert json.loads(recovered.result_json or "{}") == result
        assert reopened.list_recovery_candidates(TENANT) == ()

def test_side_effect_marker_is_monotonic() -> None:
    with TemporaryDirectory() as directory:
        journal = SQLiteExecutionJournal(f"{directory}/journal.sqlite")
        assert journal.create(record())
        journal.transition(TENANT, EXECUTION_ID, JournalState.RUNNING, side_effect_started=True)
        with pytest.raises(ValueError, match="cannot be cleared"):
            journal.transition(
                TENANT,
                EXECUTION_ID,
                JournalState.AUTHORIZED,
                side_effect_started=False,
            )

def test_idempotency_identity_is_unique_per_tenant() -> None:
    with TemporaryDirectory() as directory:
        journal = SQLiteExecutionJournal(f"{directory}/journal.sqlite")
        assert journal.create(record())
        assert journal.create(record(execution_id=uuid4())) is False
        assert journal.create(record(execution_id=uuid4(), key="idem-1-tenant-2")) is True

def test_invalid_database_path_is_rejected() -> None:
    with pytest.raises(ValueError):
        SQLiteExecutionJournal("   ")