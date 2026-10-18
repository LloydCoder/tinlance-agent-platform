from datetime import UTC, datetime
from uuid import UUID

import pytest

from tinlance_agent_platform_events.publisher import PostgresOutboxPublisher

TENANT_ID = UUID("00000000-0000-0000-0000-000000000061")
RUN_ID = UUID("40000000-0000-0000-0000-000000000061")
EVENT_ID = UUID("50000000-0000-0000-0000-000000000061")
OUTBOX_ID = UUID("60000000-0000-0000-0000-000000000061")
LEASE_TOKEN = UUID("70000000-0000-0000-0000-000000000061")


class FakeCursor:
    def __init__(self, row=None, rows=None):
        self.row = row
        self.rows = rows or []

    def fetchone(self):
        return self.row

    def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(
        self,
        *,
        claim_rows=None,
        event_row=None,
        ack_result=True,
        release_result=True,
        autocommit=False,
    ):
        self.claim_rows = claim_rows or []
        self.event_row = event_row
        self.ack_result = ack_result
        self.release_result = release_result
        self.autocommit = autocommit
        self.queries = []
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def execute(self, query, params=()):
        self.queries.append((query, params))
        if "claim_outbox_batch" in query:
            return FakeCursor(rows=self.claim_rows)
        if "FROM platform.events" in query:
            return FakeCursor(row=self.event_row)
        if "platform.ack_outbox" in query:
            return FakeCursor((self.ack_result,))
        if "platform.release_outbox" in query:
            return FakeCursor((self.release_result,))
        return FakeCursor(("tenant-scope-set",))

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def event_row(*, tenant_id=TENANT_ID, payload=None, trace_id="4bf92f3577b34da6a3ce929d0e0e4736"):
    return (
        EVENT_ID,
        tenant_id,
        RUN_ID,
        "com.tinlance.execution.completed.v1",
        payload if payload is not None else {"state": "succeeded"},
        datetime(2026, 10, 18, 4, 0, tzinfo=UTC),
        "https://tinlance.com/platform/runs",
        "workflow-001",
        None,
        trace_id,
        "00f067aa0ba902b7",
        None,
        "internal",
    )


def make_publisher(connection_factory, publish):
    return PostgresOutboxPublisher(
        tenant_id=str(TENANT_ID),
        connection_factory=connection_factory,
        publish=publish,
        retry_base_seconds=0,
    )


def test_publisher_claims_validates_publishes_and_acknowledges() -> None:
    connections = []
    def factory():
        connection = FakeConnection(
            claim_rows=[(OUTBOX_ID, EVENT_ID, LEASE_TOKEN, 1)],
            event_row=event_row(),
        )
        connections.append(connection)
        return connection

    published = []
    result = make_publisher(factory, published.append).poll_once(limit=1, lease_seconds=30)

    assert result.claimed == 1
    assert result.published == 1
    assert result.failed == 0
    assert result.acknowledgement_failed == 0
    assert published[0].as_payload()["tenantid"] == str(TENANT_ID)
    assert published[0].as_payload()["executionid"] == str(RUN_ID)
    assert all(connection.committed for connection in connections)
    assert all(connection.closed for connection in connections)
    assert any(
        "platform.ack_outbox" in query
        for connection in connections
        for query, _ in connection.queries
    )


def test_provider_failure_releases_with_stable_code_not_exception_text() -> None:
    connections = []
    def factory():
        connection = FakeConnection(
            claim_rows=[(OUTBOX_ID, EVENT_ID, LEASE_TOKEN, 1)],
            event_row=event_row(),
        )
        connections.append(connection)
        return connection

    def fail_publish(_envelope):
        raise RuntimeError("secret token=do-not-log")

    result = make_publisher(factory, fail_publish).poll_once(limit=1, lease_seconds=30)
    assert result.claimed == 1
    assert result.published == 0
    assert result.failed == 1
    release = [
        params
        for connection in connections
        for query, params in connection.queries
        if "platform.release_outbox" in query
    ]
    assert release == [(OUTBOX_ID, LEASE_TOKEN, "provider_publish_failed", 0)]


def test_invalid_sensitive_event_is_released_without_publication() -> None:
    connections = []
    def factory():
        connection = FakeConnection(
            claim_rows=[(OUTBOX_ID, EVENT_ID, LEASE_TOKEN, 1)],
            event_row=event_row(payload={"api_token": "sensitive"}),
        )
        connections.append(connection)
        return connection

    published = []
    result = make_publisher(factory, published.append).poll_once(limit=1, lease_seconds=30)
    assert result.failed == 1
    assert published == []
    assert any(
        params[2] == "event_invalid"
        for connection in connections
        for query, params in connection.queries
        if "platform.release_outbox" in query
    )


def test_tenant_mismatch_is_rejected_before_publish() -> None:
    connections = []
    def factory():
        connection = FakeConnection(
            claim_rows=[(OUTBOX_ID, EVENT_ID, LEASE_TOKEN, 1)],
            event_row=event_row(tenant_id=UUID("00000000-0000-0000-0000-000000000062")),
        )
        connections.append(connection)
        return connection

    published = []
    result = make_publisher(factory, published.append).poll_once(limit=1, lease_seconds=30)
    assert result.failed == 1
    assert published == []


def test_stale_ack_is_reported_as_possible_duplicate_delivery() -> None:
    connections = []
    def factory():
        connection = FakeConnection(
            claim_rows=[(OUTBOX_ID, EVENT_ID, LEASE_TOKEN, 1)],
            event_row=event_row(),
            ack_result=False,
        )
        connections.append(connection)
        return connection

    result = make_publisher(factory, lambda _event: None).poll_once(limit=1, lease_seconds=30)
    assert result.published == 0
    assert result.acknowledgement_failed == 1


def test_publisher_rejects_autocommit_connection() -> None:
    connections = []
    def factory():
        connection = FakeConnection(autocommit=True)
        connections.append(connection)
        return connection

    with pytest.raises(RuntimeError, match="transactional connection"):
        make_publisher(factory, lambda _event: None).poll_once()
    assert connections[0].rolled_back
    assert connections[0].closed


@pytest.mark.parametrize("limit,lease_seconds", [(0, 30), (1001, 30), (1, 0), (1, 3601)])
def test_publisher_rejects_invalid_batch_and_lease_bounds(limit, lease_seconds) -> None:
    publisher = make_publisher(lambda: FakeConnection(), lambda _event: None)
    with pytest.raises(ValueError):
        publisher.poll_once(limit=limit, lease_seconds=lease_seconds)
