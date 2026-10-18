from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from tinlance_agent_platform_events.outbox import Event, PostgresEventStore


class FakeCursor:
    def __init__(self, row=None, rows=None):
        self.row = row
        self.rows = rows or []

    def fetchone(self):
        return self.row

    def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self, *, run_exists=True, event_rows=None):
        self.run_exists = run_exists
        self.event_rows = event_rows or []
        self.queries = []
        self.committed = False

    def execute(self, query, params=()):
        self.queries.append((query, params))
        if "SELECT run_id FROM platform.runs" in query:
            return FakeCursor((params[1],) if self.run_exists else None)
        if "SELECT COALESCE(MAX(sequence)" in query:
            return FakeCursor((1,))
        if "SELECT event_id, tenant_id, run_id, event_type, payload" in query:
            return FakeCursor(rows=self.event_rows)
        return FakeCursor()

    def commit(self):
        self.committed = True


def make_event(tenant_id=None):
    return Event(
        event_id=uuid4(),
        tenant_id=str(tenant_id or UUID("00000000-0000-0000-0000-000000000051")),
        run_id=UUID("40000000-0000-0000-0000-000000000051"),
        event_type="com.tinlance.task.completed.v1",
        payload={"task": "task-1", "state": "succeeded"},
        occurred_at=datetime(2026, 10, 18, 4, 0, tzinfo=UTC),
    )


def test_postgres_append_writes_event_and_outbox_on_same_uncommitted_connection() -> None:
    connection = FakeConnection()
    store = PostgresEventStore(connection)
    event = store.append(make_event())

    assert len(connection.queries) == 4
    assert "FOR UPDATE" in connection.queries[0][0]
    assert "MAX(sequence)" in connection.queries[1][0]
    assert "INSERT INTO platform.events" in connection.queries[2][0]
    assert "INSERT INTO platform.outbox" in connection.queries[3][0]
    assert event.trace_id
    assert event.correlation_id == str(event.run_id)
    assert connection.committed is False


def test_postgres_append_rejects_run_outside_tenant_scope() -> None:
    connection = FakeConnection(run_exists=False)
    with pytest.raises(ValueError, match="run does not exist"):
        PostgresEventStore(connection).append(make_event())
    assert len(connection.queries) == 1
    assert connection.committed is False


def test_postgres_append_requires_uuid_tenant_id() -> None:
    connection = FakeConnection()
    with pytest.raises(ValueError, match="tenant_id must be a UUID"):
        PostgresEventStore(connection).append(make_event(tenant_id="tenant-a"))
    assert connection.queries == []


def test_postgres_list_for_run_rehydrates_rows() -> None:
    tenant_id = UUID("00000000-0000-0000-0000-000000000051")
    run_id = UUID("40000000-0000-0000-0000-000000000051")
    event_id = uuid4()
    row = (
        event_id,
        tenant_id,
        run_id,
        "com.tinlance.task.completed.v1",
        {"task": "task-1", "state": "succeeded"},
        datetime(2026, 10, 18, 4, 0, tzinfo=UTC),
        "urn:tinlance:agent-platform",
        str(run_id),
        None,
        "4bf92f3577b34da6a3ce929d0e0e4736",
        None,
        None,
        "internal",
    )
    connection = FakeConnection(event_rows=[row])
    events = PostgresEventStore(connection).list_for_run(str(tenant_id), run_id)
    assert len(events) == 1
    assert events[0].event_id == event_id
    assert events[0].payload["state"] == "succeeded"
    assert events[0].trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
