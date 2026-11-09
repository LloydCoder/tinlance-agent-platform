from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from tinlance_agent_platform_durability.postgres_restore_ledger import (
    PostgresRestoreLedger,
)

TENANT = UUID("10000000-0000-0000-0000-000000000001")
WORKSPACE = UUID("20000000-0000-0000-0000-000000000001")
RESTORE = UUID("30000000-0000-0000-0000-000000000001")
SNAPSHOT = UUID("40000000-0000-0000-0000-000000000001")


class FakeCursor:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self, rows=None, autocommit=False, fail=False):
        self.rows = list(rows or [])
        self.autocommit = autocommit
        self.fail = fail
        self.calls = []
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def execute(self, sql, params=None):
        self.calls.append((sql, params))
        if self.fail:
            raise RuntimeError("database unavailable")
        return FakeCursor(self.rows.pop(0) if self.rows else (True,))

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def test_begin_sets_tenant_scope_and_claims_once():
    connection = FakeConnection([(True,)])
    ledger = PostgresRestoreLedger(connection_factory=lambda: connection)
    assert ledger.begin(TENANT, WORKSPACE, RESTORE, SNAPSHOT, 7) is True
    assert connection.calls[0][0] == "SELECT set_config('platform.tenant_id', %s, true)"
    assert connection.calls[1][0] == (
        "SELECT platform.begin_workspace_restore(%s, %s, %s, %s, %s)"
    )
    assert connection.calls[1][1] == (TENANT, WORKSPACE, RESTORE, SNAPSHOT, 7)
    assert connection.committed and connection.closed


def test_duplicate_claim_returns_false_without_raising():
    connection = FakeConnection([(False,)])
    ledger = PostgresRestoreLedger(connection_factory=lambda: connection)
    assert ledger.begin(TENANT, WORKSPACE, RESTORE, SNAPSHOT, 7) is False
    assert connection.committed


def test_complete_and_fail_use_tenant_scoped_functions():
    connection = FakeConnection([(True,), (True,)])
    ledger = PostgresRestoreLedger(connection_factory=lambda: connection)
    digest = "a" * 64
    ledger.complete(TENANT, WORKSPACE, RESTORE, digest)
    ledger.fail(TENANT, WORKSPACE, RESTORE, "credential_refresh_failed")
    assert connection.calls[1][0] == (
        "SELECT platform.complete_workspace_restore(%s, %s, %s, %s)"
    )
    assert connection.calls[2][0] == (
        "SELECT platform.fail_workspace_restore(%s, %s, %s, %s)"
    )
    assert connection.committed


@pytest.mark.parametrize("digest", ["", "A" * 64, "g" * 64, "a" * 63])
def test_complete_rejects_invalid_snapshot_digest(digest):
    ledger = PostgresRestoreLedger(connection_factory=lambda: FakeConnection())
    with pytest.raises(ValueError, match="SHA-256"):
        ledger.complete(TENANT, WORKSPACE, RESTORE, digest)


@pytest.mark.parametrize("reason", ["", "sensitive token value", "x" * 65, "bad/code"])
def test_fail_rejects_unstructured_failure_reason(reason):
    ledger = PostgresRestoreLedger(connection_factory=lambda: FakeConnection())
    with pytest.raises(ValueError, match="normalized"):
        ledger.fail(TENANT, WORKSPACE, RESTORE, reason)


def test_begin_rejects_non_uuid_and_non_positive_or_boolean_fence():
    ledger = PostgresRestoreLedger(connection_factory=lambda: FakeConnection())
    with pytest.raises(TypeError):
        ledger.begin("tenant", WORKSPACE, RESTORE, SNAPSHOT, 1)
    with pytest.raises(ValueError):
        ledger.begin(TENANT, WORKSPACE, RESTORE, SNAPSHOT, 0)
    with pytest.raises(ValueError):
        ledger.begin(TENANT, WORKSPACE, RESTORE, SNAPSHOT, True)


def test_database_error_rolls_back_and_closes_connection():
    connection = FakeConnection(fail=True)
    ledger = PostgresRestoreLedger(connection_factory=lambda: connection)
    with pytest.raises(RuntimeError, match="database unavailable"):
        ledger.begin(TENANT, WORKSPACE, RESTORE, SNAPSHOT, 1)
    assert connection.rolled_back and connection.closed
    assert not connection.committed


def test_autocommit_connections_are_rejected():
    connection = FakeConnection(autocommit=True)
    ledger = PostgresRestoreLedger(connection_factory=lambda: connection)
    with pytest.raises(RuntimeError, match="explicit transactions"):
        ledger.begin(TENANT, WORKSPACE, RESTORE, SNAPSHOT, 1)
    assert connection.closed


def test_terminal_transition_requires_existing_started_operation():
    connection = FakeConnection([(False,)])
    ledger = PostgresRestoreLedger(connection_factory=lambda: connection)
    with pytest.raises(RuntimeError, match="cannot transition"):
        ledger.complete(TENANT, WORKSPACE, RESTORE, "a" * 64)
