from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from tinlance_agent_platform_api import APIRequest, APIResponse
from tinlance_agent_platform_api.postgres_idempotency import (
    IdempotencyInProgressError,
    IdempotencyOutcomeUnknownError,
    PostgresAPIIdempotencyStore,
)
from tinlance_agent_platform_api.service import IdempotencyConflictError

TENANT_ID = UUID("00000000-0000-0000-0000-000000000092")
FINGERPRINT = "b" * 64
KEY = "durable-replay-key-0001"


class Cursor:
    def __init__(self, row=None):
        self.row = row

    def fetchone(self):
        return self.row


class Connection:
    def __init__(self, *, inserted=None, selected=None, updated=None):
        self.inserted = inserted
        self.selected = selected
        self.updated = updated
        self.queries = []
        self.committed = False
        self.rolled_back = False
        self.closed = False
        self.autocommit = False

    def execute(self, query, params=()):
        self.queries.append((query, params))
        if "INSERT INTO platform.api_idempotency_records" in query:
            return Cursor(self.inserted)
        if "SELECT request_fingerprint" in query:
            return Cursor(self.selected)
        if "UPDATE platform.api_idempotency_records" in query:
            return Cursor(self.updated)
        return Cursor(("ok",))

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def request() -> APIRequest:
    return APIRequest(
        tenant_id=str(TENANT_ID),
        subject_id="user-a",
        operation="extensions.outbox.dead_letter.replay",
        payload={"event_id": "event-1"},
        request_id="request-1",
        idempotency_key=KEY,
    )


def record(status, *, fingerprint=FINGERPRINT, lease_expires_at=None):
    return (
        fingerprint,
        "extensions.outbox.dead_letter.replay",
        status,
        "success" if status == "completed" else None,
        {"status": "requeued"} if status == "completed" else None,
        lease_expires_at,
    )


def test_postgres_idempotency_reserves_executes_and_persists_response():
    reserve = Connection(inserted=("reserved",))
    complete = Connection(updated=("completed",))
    connections = iter((reserve, complete))
    store = PostgresAPIIdempotencyStore(connection_factory=lambda: next(connections))
    calls = []

    response = store.execute_once(
        request(),
        FINGERPRINT,
        lambda: calls.append("called") or APIResponse("success", {"status": "requeued"}),
    )

    assert response == APIResponse("success", {"status": "requeued"})
    assert calls == ["called"]
    assert reserve.committed and complete.committed
    assert reserve.closed and complete.closed
    assert any("set_config('platform.tenant_id'" in query for query, _ in reserve.queries)
    assert any("status = 'completed'" in query for query, _ in complete.queries)


def test_postgres_idempotency_returns_completed_response_without_reexecution():
    connection = Connection(
        inserted=None,
        selected=record("completed"),
    )
    store = PostgresAPIIdempotencyStore(connection_factory=lambda: connection)
    calls = []

    response = store.execute_once(
        request(),
        FINGERPRINT,
        lambda: calls.append("must-not-run") or APIResponse("wrong", {}),
    )

    assert response == APIResponse("success", {"status": "requeued"})
    assert calls == []
    assert connection.committed


def test_postgres_idempotency_rejects_same_key_with_different_fingerprint():
    connection = Connection(inserted=None, selected=record("completed", fingerprint="c" * 64))
    store = PostgresAPIIdempotencyStore(connection_factory=lambda: connection)

    with pytest.raises(IdempotencyConflictError):
        store.execute_once(request(), FINGERPRINT, lambda: APIResponse("success", {}))


def test_postgres_idempotency_does_not_reexecute_an_active_reservation():
    connection = Connection(
        inserted=None,
        selected=record("processing", lease_expires_at=datetime.now(UTC) + timedelta(minutes=1)),
    )
    store = PostgresAPIIdempotencyStore(connection_factory=lambda: connection)

    with pytest.raises(IdempotencyInProgressError):
        store.execute_once(request(), FINGERPRINT, lambda: APIResponse("success", {}))


def test_postgres_idempotency_marks_expired_reservation_unknown_not_retryable():
    connection = Connection(
        inserted=None,
        selected=record("processing", lease_expires_at=datetime.now(UTC) - timedelta(seconds=1)),
        updated=("outcome_unknown",),
    )
    store = PostgresAPIIdempotencyStore(connection_factory=lambda: connection)

    with pytest.raises(IdempotencyOutcomeUnknownError):
        store.execute_once(request(), FINGERPRINT, lambda: APIResponse("success", {}))
    assert any("status = 'outcome_unknown'" in query for query, _ in connection.queries)


def test_postgres_idempotency_marks_handler_exception_as_unknown():
    reserve = Connection(inserted=("reserved",))
    unknown = Connection(updated=("outcome_unknown",))
    connections = iter((reserve, unknown))
    store = PostgresAPIIdempotencyStore(connection_factory=lambda: next(connections))

    def fail():
        raise TimeoutError("downstream outcome cannot be proven")

    with pytest.raises(TimeoutError):
        store.execute_once(request(), FINGERPRINT, fail)
    assert any("status = 'outcome_unknown'" in query for query, _ in unknown.queries)
