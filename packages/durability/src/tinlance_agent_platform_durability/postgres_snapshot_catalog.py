"""Tenant-scoped PostgreSQL catalog for immutable workspace snapshot references."""

from __future__ import annotations

import re
from collections.abc import Callable
from contextlib import suppress
from datetime import datetime
from typing import Any
from uuid import UUID

from .snapshots import SnapshotConflictError, SnapshotReference


class PostgresSnapshotCatalog:
    """Persist and resolve snapshot metadata through tenant-scoped SQL functions."""

    _DIGEST = re.compile(r"^[0-9a-f]{64}$")

    def __init__(self, *, connection_factory: Callable[[], Any]) -> None:
        self._connection_factory = connection_factory

    def _transaction(self, tenant_id: UUID, operation: Callable[[Any], Any]) -> Any:
        if not isinstance(tenant_id, UUID):
            raise TypeError("tenant_id must be a UUID")
        connection = self._connection_factory()
        try:
            if getattr(connection, "autocommit", False):
                raise RuntimeError("PostgresSnapshotCatalog requires explicit transactions")
            connection.execute(
                "SELECT set_config('platform.tenant_id', %s, true)",
                (str(tenant_id),),
            )
            result = operation(connection)
            connection.commit()
            return result
        except BaseException:
            with suppress(Exception):
                connection.rollback()
            raise
        finally:
            with suppress(Exception):
                connection.close()

    def record(self, reference: SnapshotReference) -> None:
        if not isinstance(reference, SnapshotReference):
            raise TypeError("reference must be a SnapshotReference")
        if not self._DIGEST.fullmatch(reference.digest):
            raise ValueError("snapshot digest must be lowercase SHA-256 hex")
        if reference.created_at.tzinfo is None or reference.created_at.utcoffset() is None:
            raise ValueError("snapshot timestamp must be timezone-aware")

        def operation(connection: Any) -> None:
            row = connection.execute(
                "SELECT platform.record_workspace_snapshot(%s, %s, %s, %s, %s, %s, %s)",
                (
                    reference.tenant_id,
                    reference.snapshot_id,
                    reference.workspace_id,
                    reference.fencing_token,
                    reference.created_at,
                    reference.digest,
                    reference.snapshot_id.hex + ".snapshot",
                ),
            ).fetchone()
            if row is None or row[0] is not True:
                raise SnapshotConflictError("snapshot catalog reference already exists")

        self._transaction(reference.tenant_id, operation)

    def get(
        self, tenant_id: UUID, workspace_id: UUID, snapshot_id: UUID
    ) -> SnapshotReference | None:
        if not all(isinstance(value, UUID) for value in (tenant_id, workspace_id, snapshot_id)):
            raise TypeError("tenant_id, workspace_id and snapshot_id must be UUID values")

        def operation(connection: Any) -> SnapshotReference | None:
            row = connection.execute(
                "SELECT * FROM platform.get_workspace_snapshot(%s, %s, %s)",
                (tenant_id, workspace_id, snapshot_id),
            ).fetchone()
            if row is None:
                return None
            stored_id, stored_tenant, stored_workspace, fence, created_at, digest, status = row
            if (
                stored_id != snapshot_id
                or stored_tenant != tenant_id
                or stored_workspace != workspace_id
                or status != "available"
                or not isinstance(fence, int)
                or not isinstance(created_at, datetime)
                or not isinstance(digest, str)
                or not self._DIGEST.fullmatch(digest)
            ):
                raise RuntimeError("snapshot catalog returned invalid metadata")
            return SnapshotReference(
                snapshot_id=stored_id,
                tenant_id=stored_tenant,
                workspace_id=stored_workspace,
                fencing_token=fence,
                created_at=created_at,
                digest=digest,
            )

        return self._transaction(tenant_id, operation)
