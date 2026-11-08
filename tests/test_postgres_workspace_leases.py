from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from tinlance_agent_platform_durability import PostgresWorkspaceLeaseStore, WorkspaceLease

TENANT = UUID("00000000-0000-0000-0000-000000000092")
WORKSPACE = UUID("20000000-0000-0000-0000-000000000092")
LEASE = UUID("30000000-0000-0000-0000-000000000092")
EXPIRES = datetime.now(UTC) + timedelta(minutes=10)


class Cursor:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class Connection:
    def __init__(self, row=None, *, error=None):
        self.row = row
        self.error = error
        self.queries = []
        self.committed = False
        self.rolled_back = False
        self.closed = False
        self.autocommit = False

    def execute(self, query, params=()):
        self.queries.append((query, params))
        if self.error is not None:
            raise self.error
        return Cursor(self.row)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def lease_row(token=1):
    return (LEASE, TENANT, WORKSPACE, "owner-a", "worker-a", token, EXPIRES)


def lease():
    return WorkspaceLease(TENANT, WORKSPACE, LEASE, "owner-a", "worker-a", 1, EXPIRES)


def test_acquire_returns_fenced_lease_and_owns_tenant_transaction():
    connection = Connection(lease_row())
    store = PostgresWorkspaceLeaseStore(connection_factory=lambda: connection)

    result = store.acquire(TENANT, WORKSPACE, "owner-a", "worker-a", lease_seconds=600)

    assert result == lease()
    assert connection.committed
    assert connection.closed
    assert any("set_config('platform.tenant_id'" in query for query, _ in connection.queries)
    assert any("platform.acquire_workspace_lease" in query for query, _ in connection.queries)


def test_acquire_returns_none_when_an_unexpired_owner_already_holds_lease():
    connection = Connection(None)
    store = PostgresWorkspaceLeaseStore(connection_factory=lambda: connection)

    assert store.acquire(TENANT, WORKSPACE, "owner-b", "worker-b") is None
    assert connection.committed


def test_renew_uses_the_exact_lease_and_fencing_token():
    renewed = datetime.now(UTC) + timedelta(minutes=15)
    connection = Connection((renewed,))
    store = PostgresWorkspaceLeaseStore(connection_factory=lambda: connection)

    assert store.renew(lease(), lease_seconds=900) == renewed
    query, params = connection.queries[-1]
    assert "platform.renew_workspace_lease" in query
    assert params == (TENANT, WORKSPACE, LEASE, 1, "owner-a", "worker-a", 900)


def test_assert_active_returns_database_fencing_decision():
    connection = Connection((False,))
    store = PostgresWorkspaceLeaseStore(connection_factory=lambda: connection)

    assert store.assert_active(lease()) is False
    assert "platform.assert_workspace_lease" in connection.queries[-1][0]


def test_revoke_and_release_return_durable_transition_results():
    revoke_connection = Connection((True,))
    release_connection = Connection((True,))
    revoke_store = PostgresWorkspaceLeaseStore(connection_factory=lambda: revoke_connection)
    release_store = PostgresWorkspaceLeaseStore(connection_factory=lambda: release_connection)

    assert revoke_store.revoke(lease()) is True
    assert release_store.release(lease()) is True
    assert "platform.revoke_workspace_lease" in revoke_connection.queries[-1][0]
    assert "platform.release_workspace_lease" in release_connection.queries[-1][0]


def test_database_failure_rolls_back_and_closes_connection():
    connection = Connection(error=RuntimeError("database unavailable"))
    store = PostgresWorkspaceLeaseStore(connection_factory=lambda: connection)

    with pytest.raises(RuntimeError, match="database unavailable"):
        store.acquire(TENANT, WORKSPACE, "owner-a", "worker-a")

    assert connection.rolled_back
    assert connection.closed
    assert not connection.committed


@pytest.mark.parametrize("lease_seconds", [True, 0, 59, 3601])
def test_acquire_rejects_invalid_lease_duration(lease_seconds):
    store = PostgresWorkspaceLeaseStore(connection_factory=lambda: Connection(lease_row()))

    with pytest.raises(ValueError, match="lease_seconds"):
        store.acquire(TENANT, WORKSPACE, "owner-a", "worker-a", lease_seconds=lease_seconds)


@pytest.mark.parametrize(
    ("owner", "worker"),
    [("", "worker-a"), (" owner", "worker-a"), ("owner-a", ""), ("owner-a", "worker\n")],
)
def test_acquire_rejects_untrusted_identity_strings(owner, worker):
    store = PostgresWorkspaceLeaseStore(connection_factory=lambda: Connection(lease_row()))

    with pytest.raises(ValueError):
        store.acquire(TENANT, WORKSPACE, owner, worker)
