"""Tenant-scoped PostgreSQL ledger for one-shot workspace restore operations."""

from __future__ import annotations

import re
from collections.abc import Callable
from contextlib import suppress
from typing import Any
from uuid import UUID


class PostgresRestoreLedger:
    """Persist restore claims and terminal transitions under PostgreSQL RLS.

    A restore ID is unique within a tenant and can never be replayed, including
    after failure. A retry must use a fresh restore ID and a newer lease fence.
    """

    _DIGEST = re.compile(r"^[0-9a-f]{64}$")
    _REASON = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")

    def __init__(self, *, connection_factory: Callable[[], Any]) -> None:
        self._connection_factory = connection_factory

    @staticmethod
    def _identity(tenant_id: UUID, workspace_id: UUID, restore_id: UUID) -> None:
        if not all(isinstance(value, UUID) for value in (tenant_id, workspace_id, restore_id)):
            raise TypeError("tenant_id, workspace_id and restore_id must be UUID values")

    @staticmethod
    def _fence(value: int) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError("fencing_token must be a positive integer")

    def _transaction(self, tenant_id: UUID, operation: Callable[[Any], Any]) -> Any:
        connection = self._connection_factory()
        try:
            if getattr(connection, "autocommit", False):
                raise RuntimeError("PostgresRestoreLedger requires explicit transactions")
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

    def begin(
        self,
        tenant_id: UUID,
        workspace_id: UUID,
        restore_id: UUID,
        snapshot_id: UUID,
        fencing_token: int,
    ) -> bool:
        self._identity(tenant_id, workspace_id, restore_id)
        if not isinstance(snapshot_id, UUID):
            raise TypeError("snapshot_id must be a UUID")
        self._fence(fencing_token)

        def operation(connection: Any) -> bool:
            row = connection.execute(
                "SELECT platform.begin_workspace_restore(%s, %s, %s, %s, %s)",
                (tenant_id, workspace_id, restore_id, snapshot_id, fencing_token),
            ).fetchone()
            if row is None or not isinstance(row[0], bool):
                raise RuntimeError("workspace restore begin returned an unexpected result")
            return row[0]

        return bool(self._transaction(tenant_id, operation))

    def complete(
        self,
        tenant_id: UUID,
        workspace_id: UUID,
        restore_id: UUID,
        snapshot_digest: str,
    ) -> None:
        self._identity(tenant_id, workspace_id, restore_id)
        if not isinstance(snapshot_digest, str) or not self._DIGEST.fullmatch(snapshot_digest):
            raise ValueError("snapshot_digest must be a lowercase SHA-256 hex digest")

        def operation(connection: Any) -> None:
            row = connection.execute(
                "SELECT platform.complete_workspace_restore(%s, %s, %s, %s)",
                (tenant_id, workspace_id, restore_id, snapshot_digest),
            ).fetchone()
            if row is None or row[0] is not True:
                raise RuntimeError("workspace restore cannot transition to completed")

        self._transaction(tenant_id, operation)

    def fail(
        self,
        tenant_id: UUID,
        workspace_id: UUID,
        restore_id: UUID,
        reason_code: str,
    ) -> None:
        self._identity(tenant_id, workspace_id, restore_id)
        if not isinstance(reason_code, str) or not self._REASON.fullmatch(reason_code):
            raise ValueError("reason_code must be a normalized non-sensitive code")

        def operation(connection: Any) -> None:
            row = connection.execute(
                "SELECT platform.fail_workspace_restore(%s, %s, %s, %s)",
                (tenant_id, workspace_id, restore_id, reason_code),
            ).fetchone()
            if row is None or row[0] is not True:
                raise RuntimeError("workspace restore cannot transition to failed")

        self._transaction(tenant_id, operation)
