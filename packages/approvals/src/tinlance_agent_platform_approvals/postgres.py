"""Tenant-scoped PostgreSQL approval authority for production composition."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from tinlance_agent_platform_contracts import ApprovalRequest, ApprovalStatus

_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_COLUMNS = """
    approval_id, tenant_id, run_id, action, resource, reason, requested_by,
    status, metadata, expires_at, intent_fingerprint, approved_by, consumed_at
"""


class PostgresApprovalService:
    """Durable approval lifecycle; each operation owns a short tenant-scoped transaction.

    Unlike the in-memory reference service, this adapter persists approval state and
    serializes decisions/one-time consumption with row locks. The caller supplies a
    connection factory; this class commits and closes only the connections it creates.
    """

    def __init__(self, *, connection_factory: Callable[[], Any]) -> None:
        self._connection_factory = connection_factory

    @staticmethod
    def _tenant_uuid(tenant_id: str) -> UUID:
        try:
            return UUID(tenant_id)
        except (ValueError, AttributeError) as exc:
            raise ValueError("PostgreSQL approval tenant ID must be a UUID") from exc

    def _transaction(self, tenant_id: str, operation: Callable[[Any, UUID], Any]) -> Any:
        tenant_uuid = self._tenant_uuid(tenant_id)
        connection = self._connection_factory()
        try:
            if getattr(connection, "autocommit", False):
                raise RuntimeError("PostgresApprovalService requires explicit transaction ownership")
            connection.execute(
                "SELECT set_config('platform.tenant_id', %s, true)",
                (str(tenant_uuid),),
            )
            result = operation(connection, tenant_uuid)
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
    def _from_row(row: Any) -> ApprovalRequest:
        if row is None or len(row) != 13:
            raise RuntimeError("PostgreSQL approval row has an unexpected shape")
        metadata = row[8]
        if isinstance(metadata, str):
            metadata = json.loads(metadata)
        if not isinstance(metadata, dict):
            raise RuntimeError("PostgreSQL approval metadata is not an object")
        return ApprovalRequest(
            approval_id=row[0],
            tenant_id=str(row[1]),
            run_id=row[2],
            action=row[3],
            resource=row[4],
            reason=row[5],
            requested_by=row[6],
            status=ApprovalStatus(row[7]),
            metadata=metadata,
            expires_at=row[9],
            intent_fingerprint=row[10],
            approved_by=row[11],
            consumed_at=row[12],
        )

    @staticmethod
    def _record_event(
        connection: Any,
        *,
        tenant_id: UUID,
        approval_id: UUID,
        event_type: str,
        actor_subject_id: str | None,
        intent_fingerprint: str | None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO platform.action_approval_events (
                event_id, tenant_id, approval_id, event_type,
                actor_subject_id, intent_fingerprint
            ) VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                uuid4(),
                tenant_id,
                approval_id,
                event_type,
                actor_subject_id,
                intent_fingerprint,
            ),
        )

    def request(
        self,
        tenant_id: str,
        run_id: UUID,
        action: str,
        resource: str,
        reason: str,
        requested_by: str,
        *,
        expires_at: datetime | None = None,
        intent_fingerprint: str | None = None,
    ) -> ApprovalRequest:
        fields = (tenant_id, action, resource, reason, requested_by)
        if not all(fields) or any(value != value.strip() for value in fields):
            raise ValueError("approval request fields must be normalized and non-empty")
        if not isinstance(run_id, UUID):
            raise TypeError("approval run_id must be a UUID")
        if expires_at is not None and expires_at <= datetime.now(UTC):
            raise ValueError("approval expiry must be in the future")
        if intent_fingerprint is not None and not _FINGERPRINT.fullmatch(intent_fingerprint):
            raise ValueError("approval intent fingerprint must be a SHA-256 hex digest")
        approval_id = uuid4()

        def operation(connection: Any, tenant_uuid: UUID) -> ApprovalRequest:
            row = connection.execute(
                f"""
                INSERT INTO platform.action_approvals (
                    approval_id, tenant_id, run_id, action, resource, reason,
                    requested_by, status, metadata, expires_at, intent_fingerprint
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending', '{{}}'::jsonb, %s, %s)
                RETURNING {_COLUMNS}
                """,
                (
                    approval_id,
                    tenant_uuid,
                    run_id,
                    action,
                    resource,
                    reason,
                    requested_by,
                    expires_at,
                    intent_fingerprint,
                ),
            ).fetchone()
            if row is None:
                raise RuntimeError("PostgreSQL approval insert returned no row")
            item = self._from_row(row)
            self._record_event(
                connection,
                tenant_id=tenant_uuid,
                approval_id=approval_id,
                event_type="requested",
                actor_subject_id=requested_by,
                intent_fingerprint=intent_fingerprint,
            )
            return item

        return self._transaction(tenant_id, operation)

    def _current(self, connection: Any, approval_id: UUID, tenant_uuid: UUID) -> ApprovalRequest:
        row = connection.execute(
            f"""
            SELECT {_COLUMNS}
            FROM platform.action_approvals
            WHERE approval_id = %s AND tenant_id = %s
            FOR UPDATE
            """,
            (approval_id, tenant_uuid),
        ).fetchone()
        if row is None:
            raise PermissionError("approval does not exist in the authenticated tenant scope")
        current = self._from_row(row)
        if (
            current.status is ApprovalStatus.PENDING
            and current.expires_at is not None
            and current.expires_at <= datetime.now(UTC)
        ):
            expired = connection.execute(
                f"""
                UPDATE platform.action_approvals
                SET status = 'expired', decided_at = now()
                WHERE approval_id = %s AND tenant_id = %s AND status = 'pending'
                RETURNING {_COLUMNS}
                """,
                (approval_id, tenant_uuid),
            ).fetchone()
            if expired is not None:
                current = self._from_row(expired)
                self._record_event(
                    connection,
                    tenant_id=tenant_uuid,
                    approval_id=approval_id,
                    event_type="expired",
                    actor_subject_id=None,
                    intent_fingerprint=current.intent_fingerprint,
                )
        return current

    def decide(
        self,
        approval_id: UUID,
        approved: bool,
        tenant_id: str,
        approver_subject_id: str | None = None,
        *,
        intent_fingerprint: str | None = None,
    ) -> ApprovalRequest:
        if approver_subject_id is None or not approver_subject_id.strip():
            raise PermissionError("authenticated approver identity is required")
        if approver_subject_id != approver_subject_id.strip():
            raise ValueError("approver identity must be normalized")

        def operation(connection: Any, tenant_uuid: UUID) -> ApprovalRequest:
            current = self._current(connection, approval_id, tenant_uuid)
            if current.status is not ApprovalStatus.PENDING:
                raise ValueError("approval is no longer pending")
            if intent_fingerprint is not None and current.intent_fingerprint != intent_fingerprint:
                raise PermissionError("approval intent does not match")
            if approved and approver_subject_id == current.requested_by:
                raise PermissionError("requester cannot approve the same consequential request")
            status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
            row = connection.execute(
                f"""
                UPDATE platform.action_approvals
                SET status = %s, approved_by = %s, decided_at = now()
                WHERE approval_id = %s AND tenant_id = %s AND status = 'pending'
                RETURNING {_COLUMNS}
                """,
                (status.value, approver_subject_id, approval_id, tenant_uuid),
            ).fetchone()
            if row is None:
                raise ValueError("approval is no longer pending")
            item = self._from_row(row)
            self._record_event(
                connection,
                tenant_id=tenant_uuid,
                approval_id=approval_id,
                event_type=status.value,
                actor_subject_id=approver_subject_id,
                intent_fingerprint=current.intent_fingerprint,
            )
            return item

        return self._transaction(tenant_id, operation)

    def validate_approved_for(
        self,
        approval_id: UUID,
        tenant_id: str,
        run_id: UUID,
        action: str,
        resource: str,
        *,
        intent_fingerprint: str | None = None,
    ) -> ApprovalStatus:
        def operation(connection: Any, tenant_uuid: UUID) -> ApprovalStatus:
            current = self._current(connection, approval_id, tenant_uuid)
            if current.status is ApprovalStatus.APPROVED:
                self._assert_binding(
                    current,
                    tenant_id=str(tenant_uuid),
                    run_id=run_id,
                    action=action,
                    resource=resource,
                    intent_fingerprint=intent_fingerprint,
                )
            return current.status

        return self._transaction(tenant_id, operation)

    def require_approved_for(
        self,
        approval_id: UUID,
        tenant_id: str,
        run_id: UUID,
        action: str,
        resource: str,
        *,
        intent_fingerprint: str | None = None,
    ) -> None:
        def operation(connection: Any, tenant_uuid: UUID) -> None:
            current = self._current(connection, approval_id, tenant_uuid)
            if current.status is not ApprovalStatus.APPROVED:
                raise PermissionError("approved human review is required")
            self._assert_binding(
                current,
                tenant_id=str(tenant_uuid),
                run_id=run_id,
                action=action,
                resource=resource,
                intent_fingerprint=intent_fingerprint,
            )
            row = connection.execute(
                f"""
                UPDATE platform.action_approvals
                SET status = 'consumed', consumed_at = now()
                WHERE approval_id = %s AND tenant_id = %s AND status = 'approved'
                RETURNING {_COLUMNS}
                """,
                (approval_id, tenant_uuid),
            ).fetchone()
            if row is None:
                raise PermissionError("approved human review is required")
            consumed = self._from_row(row)
            self._record_event(
                connection,
                tenant_id=tenant_uuid,
                approval_id=approval_id,
                event_type="consumed",
                actor_subject_id=consumed.approved_by,
                intent_fingerprint=consumed.intent_fingerprint,
            )

        self._transaction(tenant_id, operation)

    def get(self, approval_id: UUID, tenant_id: str) -> ApprovalRequest:
        return self._transaction(
            tenant_id,
            lambda connection, tenant_uuid: self._current(connection, approval_id, tenant_uuid),
        )

    @staticmethod
    def _assert_binding(
        current: ApprovalRequest,
        *,
        tenant_id: str,
        run_id: UUID,
        action: str,
        resource: str,
        intent_fingerprint: str | None,
    ) -> None:
        if (
            current.tenant_id != tenant_id
            or current.run_id != run_id
            or current.action != action
            or current.resource != resource
            or (
                intent_fingerprint is not None
                and current.intent_fingerprint not in {None, intent_fingerprint}
            )
        ):
            raise PermissionError("approval does not bind to this action")
