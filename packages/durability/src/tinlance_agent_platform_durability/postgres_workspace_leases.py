"""Durable PostgreSQL workspace leases with monotonic fencing tokens."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class WorkspaceLease:
    tenant_id: UUID
    workspace_id: UUID
    lease_id: UUID
    owner_subject_id: str
    worker_id: str
    fencing_token: int
    expires_at: datetime


class PostgresWorkspaceLeaseStore:
    """Tenant-scoped lease authority; callers must fence every consequential operation.

    Each method owns a short transaction. A new acquisition after expiry, revocation,
    or release increments the fencing token. Old workers cannot renew, assert, revoke,
    or release a lease after a newer owner has acquired it.
    """

    def __init__(self, *, connection_factory: Callable[[], Any]) -> None:
        self._connection_factory = connection_factory

    @staticmethod
    def _tenant_uuid(tenant_id: str | UUID) -> UUID:
        if isinstance(tenant_id, UUID):
            return tenant_id
        try:
            return UUID(tenant_id)
        except (ValueError, AttributeError) as exc:
            raise ValueError("workspace lease tenant ID must be a UUID") from exc

    @staticmethod
    def _identity(value: str, name: str, maximum: int) -> str:
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or len(value) > maximum
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError(f"{name} must be normalized printable text")
        return value

    def _transaction(self, tenant_id: UUID, operation: Callable[[Any], Any]) -> Any:
        connection = self._connection_factory()
        try:
            if getattr(connection, "autocommit", False):
                raise RuntimeError("PostgresWorkspaceLeaseStore requires explicit transactions")
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

    @staticmethod
    def _from_row(row: Any) -> WorkspaceLease:
        if row is None or len(row) != 7:
            raise RuntimeError("PostgreSQL workspace lease row has an unexpected shape")
        if (
            not isinstance(row[0], UUID)
            or not isinstance(row[1], UUID)
            or not isinstance(row[2], UUID)
            or not isinstance(row[3], str)
            or not isinstance(row[4], str)
            or isinstance(row[5], bool)
            or not isinstance(row[5], int)
            or not isinstance(row[6], datetime)
        ):
            raise RuntimeError("PostgreSQL workspace lease row has invalid field types")
        return WorkspaceLease(
            tenant_id=row[1],
            workspace_id=row[2],
            lease_id=row[0],
            owner_subject_id=row[3],
            worker_id=row[4],
            fencing_token=row[5],
            expires_at=row[6],
        )

    def acquire(
        self,
        tenant_id: str | UUID,
        workspace_id: UUID,
        owner_subject_id: str,
        worker_id: str,
        *,
        lease_seconds: int = 900,
    ) -> WorkspaceLease | None:
        tenant = self._tenant_uuid(tenant_id)
        if not isinstance(workspace_id, UUID):
            raise TypeError("workspace_id must be a UUID")
        owner = self._identity(owner_subject_id, "owner_subject_id", 512)
        worker = self._identity(worker_id, "worker_id", 256)
        if (
            isinstance(lease_seconds, bool)
            or not isinstance(lease_seconds, int)
            or not 60 <= lease_seconds <= 3600
        ):
            raise ValueError("lease_seconds must be between 60 and 3600")
        lease_id = uuid4()

        def operation(connection: Any) -> WorkspaceLease | None:
            row = connection.execute(
                "SELECT * FROM platform.acquire_workspace_lease(%s, %s, %s, %s, %s, %s)",
                (tenant, workspace_id, lease_id, owner, worker, lease_seconds),
            ).fetchone()
            return None if row is None else self._from_row(row)

        return cast(WorkspaceLease | None, self._transaction(tenant, operation))

    def renew(self, lease: WorkspaceLease, *, lease_seconds: int = 900) -> datetime:
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or not 60 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be between 60 and 3600")
        if not isinstance(lease, WorkspaceLease):
            raise TypeError("lease must be a WorkspaceLease")

        def operation(connection: Any) -> datetime:
            row = connection.execute(
                "SELECT platform.renew_workspace_lease(%s, %s, %s, %s, %s)",
                (
                    lease.tenant_id,
                    lease.workspace_id,
                    lease.lease_id,
                    lease.fencing_token,
                    lease_seconds,
                ),
            ).fetchone()
            if row is None or not isinstance(row[0], datetime):
                raise RuntimeError("workspace lease renewal returned an unexpected result")
            return row[0]

        return cast(datetime, self._transaction(lease.tenant_id, operation))

    def assert_active(self, lease: WorkspaceLease) -> bool:
        if not isinstance(lease, WorkspaceLease):
            raise TypeError("lease must be a WorkspaceLease")

        def operation(connection: Any) -> bool:
            row = connection.execute(
                "SELECT platform.assert_workspace_lease(%s, %s, %s, %s, %s, %s)",
                (
                    lease.tenant_id,
                    lease.workspace_id,
                    lease.lease_id,
                    lease.fencing_token,
                    lease.owner_subject_id,
                    lease.worker_id,
                ),
            ).fetchone()
            if row is None or not isinstance(row[0], bool):
                raise RuntimeError("workspace lease assertion returned an unexpected result")
            return row[0]

        return cast(bool, self._transaction(lease.tenant_id, operation))

    def revoke(self, lease: WorkspaceLease) -> bool:
        if not isinstance(lease, WorkspaceLease):
            raise TypeError("lease must be a WorkspaceLease")

        def operation(connection: Any) -> bool:
            row = connection.execute(
                "SELECT platform.revoke_workspace_lease(%s, %s, %s, %s)",
                (lease.tenant_id, lease.workspace_id, lease.lease_id, lease.fencing_token),
            ).fetchone()
            if row is None or not isinstance(row[0], bool):
                raise RuntimeError("workspace lease revocation returned an unexpected result")
            return row[0]

        return cast(bool, self._transaction(lease.tenant_id, operation))

    def release(self, lease: WorkspaceLease) -> bool:
        if not isinstance(lease, WorkspaceLease):
            raise TypeError("lease must be a WorkspaceLease")

        def operation(connection: Any) -> bool:
            row = connection.execute(
                "SELECT platform.release_workspace_lease(%s, %s, %s, %s)",
                (lease.tenant_id, lease.workspace_id, lease.lease_id, lease.fencing_token),
            ).fetchone()
            if row is None or not isinstance(row[0], bool):
                raise RuntimeError("workspace lease release returned an unexpected result")
            return row[0]

        return cast(bool, self._transaction(lease.tenant_id, operation))
