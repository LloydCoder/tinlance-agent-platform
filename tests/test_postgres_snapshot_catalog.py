from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from tinlance_agent_platform_durability.postgres_snapshot_catalog import (
    PostgresSnapshotCatalog,
)
from tinlance_agent_platform_durability.snapshots import SnapshotConflictError, SnapshotReference

TENANT = UUID("10000000-0000-0000-0000-000000000001")
WORKSPACE = UUID("20000000-0000-0000-0000-000000000001")
SNAPSHOT = UUID("30000000-0000-0000-0000-000000000001")
REFERENCE = SnapshotReference(
    snapshot_id=SNAPSHOT,
    tenant_id=TENANT,
    workspace_id=WORKSPACE,
    fencing_token=7,
    created_at=datetime(2026, 11, 9, tzinfo=UTC),
    digest="a" * 64,
)


class Cursor:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class Connection:
    def __init__(self, rows):
        self.rows = list(rows)
        self.calls = []
        self.autocommit = False
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def execute(self, sql, params=None):
        self.calls.append((sql, params))
        if sql.startswith("SELECT set_config"):
            return Cursor(("tenant",))
        return Cursor(self.rows.pop(0))

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def test_record_uses_tenant_scoped_database_function_and_immutable_storage_key():
    connection = Connection([(True,)])
    catalog = PostgresSnapshotCatalog(connection_factory=lambda: connection)
    catalog.record(REFERENCE)
    assert connection.calls[0][1] == (str(TENANT),)
    assert connection.calls[1][0] == (
        "SELECT platform.record_workspace_snapshot(%s, %s, %s, %s, %s, %s, %s)"
    )
    assert connection.calls[1][1][-1] == SNAPSHOT.hex + ".snapshot"
    assert connection.committed and connection.closed


def test_record_rejects_duplicate_catalog_reference():
    connection = Connection([(False,)])
    catalog = PostgresSnapshotCatalog(connection_factory=lambda: connection)
    with pytest.raises(SnapshotConflictError, match="already exists"):
        catalog.record(REFERENCE)
    assert connection.rolled_back and connection.closed


def test_get_returns_only_available_tenant_scoped_reference():
    connection = Connection(
        [(SNAPSHOT, TENANT, WORKSPACE, 7, REFERENCE.created_at, "a" * 64, "available")]
    )
    catalog = PostgresSnapshotCatalog(connection_factory=lambda: connection)
    assert catalog.get(TENANT, WORKSPACE, SNAPSHOT) == REFERENCE
    assert connection.calls[1][1] == (TENANT, WORKSPACE, SNAPSHOT)
    assert connection.committed


def test_get_returns_none_when_snapshot_is_not_catalogued():
    connection = Connection([None])
    catalog = PostgresSnapshotCatalog(connection_factory=lambda: connection)
    assert catalog.get(TENANT, WORKSPACE, SNAPSHOT) is None
    assert connection.committed


def test_catalog_rejects_autocommit_connections():
    connection = Connection([(True,)])
    connection.autocommit = True
    catalog = PostgresSnapshotCatalog(connection_factory=lambda: connection)
    with pytest.raises(RuntimeError, match="explicit transactions"):
        catalog.record(REFERENCE)
    assert connection.closed
