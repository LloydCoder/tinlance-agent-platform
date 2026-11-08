"""Tenant-scoped PostgreSQL approval authority.

All writes execute through migration-owned SECURITY DEFINER functions. The
application connection role receives read-only approval table access plus
EXECUTE on the lifecycle functions via membership in platform_approval_client.
"""

from __future__ import annotations

import contextlib
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from tinlance_agent_platform_contracts import ApprovalRequest, ApprovalStatus

_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_MAX_EXPIRY = timedelta(days=30)
_SELECT_APPROVAL = """
    SELECT approval_id, tenant_id, run_id, action, resource, reason,
           requested_by, status, metadata, expires_at, intent_fingerprint,
           approved_by, consumed_at, trace_context
      FROM platform.approvals
     WHERE tenant_id = %s AND approval_id = %s
"""


class PostgresApprovalService:
    """Durable ApprovalVerifier implementation backed by PostgreSQL."""

    def __init__(self, *, connection_factory: Callable[[], Any]) -> None:
        self._connection_factory = connection_factory

    @staticmethod
    def _tenant_uuid(tenant_id: str) -> UUID:
        if not isinstance(tenant_id, str):
            raise ValueError("tenant ID must be a canonical UUID")
        try:
            value = UUID(tenant_id)
        except ValueError as exc:
            raise ValueError("tenant ID must be a canonical UUID") from exc
        if str(value) != tenant_id:
            raise ValueError("tenant ID must be a canonical lowercase UUID")
        return value

    @staticmethod
    def _normalized_text(value: str, name: str, *, maximum: int = 256) -> str:
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or len(value) > maximum
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            raise ValueError(f"{name} must be normalized and bounded")
        return value

    @staticmethod
    def _fingerprint(value: str | None) -> str | None:
        if value is not None and (not isinstance(value, str) or not _FINGERPRINT.fullmatch(value)):
            raise ValueError("intent fingerprint must be 64 lowercase hexadecimal characters")
        return value

    def _transaction(self, tenant_id: UUID, operation: Callable[[Any], Any]) -> Any:
        connection = self._connection_factory()
        try:
            if getattr(connection, "autocommit", False):
                raise RuntimeError("PostgresApprovalService requires a caller-owned transaction")
            connection.execute(
                "SELECT set_config('platform.tenant_id', %s, true)",
                (str(tenant_id),),
            )
            result = operation(connection)
            connection.commit()
            return result
        except BaseException:
            with contextlib.suppress(Exception):
                connection.rollback()
            raise
        finally:
            with contextlib.suppress(Exception):
                connection.close()

    @staticmethod
    def _row_to_approval(row: Any) -> ApprovalRequest:
        if row is None or len(row) != 14:
            raise RuntimeError("PostgreSQL approval query returned an unexpected row")
        metadata = row[8]
        if not isinstance(metadata, dict):
            raise RuntimeError("PostgreSQL approval metadata is not a JSON object")
        return ApprovalRequest(
            approval_id=row[0],
            tenant_id=str(row[1]),
            run_id=row[2],
            action=row[3],
            resource=row[4],
            reason=row[5],
            requested_by=row[6],
            status=ApprovalStatus(row[7]),
            metadata=dict(metadata),
            expires_at=row[9],
            intent_fingerprint=row[10],
            approved_by=row[11],
            consumed_at=row[12],
            trace_context=None,
        )

    def _load(self, connection: Any, tenant_id: UUID, approval_id: UUID) -> ApprovalRequest:
        row = connection.execute(_SELECT_APPROVAL, (tenant_id, approval_id)).fetchone()
        if row is None:
            raise KeyError("approval does not exist")
        return self._row_to_approval(row)

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
        tenant = self._tenant_uuid(tenant_id)
        if not isinstance(run_id, UUID):
            raise TypeError("run_id must be a UUID")
        normalized_action = self._normalized_text(action, "action")
        normalized_resource = self._normalized_text(resource, "resource", maximum=512)
        normalized_reason = self._normalized_text(reason, "reason", maximum=1024)
        normalized_requester = self._normalized_text(requested_by, "requested_by")
        fingerprint = self._fingerprint(intent_fingerprint)
        if expires_at is not None:
            if expires_at.tzinfo is None or expires_at.utcoffset() is None:
                raise ValueError("approval expiry must be timezone-aware")
            normalized_expiry = expires_at.astimezone(UTC)
            now = datetime.now(UTC)
            if normalized_expiry <= now or normalized_expiry > now + _MAX_EXPIRY:
                raise ValueError("approval expiry must be within the next 30 days")
        else:
            normalized_expiry = None
        approval_id = uuid4()
        metadata_json = json.dumps({}, sort_keys=True, separators=(",", ":"))

        def operation(connection: Any) -> ApprovalRequest:
            row = connection.execute(
                """
                SELECT platform.request_approval(
                    %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s::jsonb
                )
                """,
                (
                    tenant,
                    approval_id,
                    run_id,
                    normalized_action,
                    normalized_resource,
                    normalized_reason,
                    normalized_requester,
                    metadata_json,
                    normalized_expiry,
                    fingerprint,
                    None,
                ),
            ).fetchone()
            if row is None or row[0] != approval_id:
                raise RuntimeError("PostgreSQL approval request returned an unexpected ID")
            return self._load(connection, tenant, approval_id)

        try:
            return self._transaction(tenant, operation)
        except Exception as exc:
            sqlstate = getattr(exc, "sqlstate", None)
            if sqlstate == "42501":
                raise PermissionError("tenant is not authorized to request this approval") from exc
            if sqlstate == "22023":
                raise ValueError("PostgreSQL rejected the approval request") from exc
            raise

    def decide(
        self,
        approval_id: UUID,
        approved: bool,
        tenant_id: str,
        approver_subject_id: str | None = None,
        *,
        intent_fingerprint: str | None = None,
    ) -> ApprovalRequest:
        tenant = self._tenant_uuid(tenant_id)
        if not isinstance(approval_id, UUID):
            raise TypeError("approval_id must be a UUID")
        if not isinstance(approved, bool):
            raise TypeError("approved must be a boolean")
        if approver_subject_id is None:
            raise PermissionError("authenticated approver identity is required")
        approver = self._normalized_text(approver_subject_id, "approver_subject_id")
        fingerprint = self._fingerprint(intent_fingerprint)

        def operation(connection: Any) -> tuple[ApprovalRequest, str]:
            row = connection.execute(
                "SELECT platform.decide_approval(%s, %s, %s, %s, %s)",
                (tenant, approval_id, approved, approver, fingerprint),
            ).fetchone()
            if row is None or row[0] not in {"approved", "rejected", "expired"}:
                raise RuntimeError("PostgreSQL approval decision returned an unexpected status")
            return self._load(connection, tenant, approval_id), row[0]

        try:
            approval, decision = self._transaction(tenant, operation)
        except Exception as exc:
            sqlstate = getattr(exc, "sqlstate", None)
            if sqlstate == "42501":
                raise PermissionError("approval decision is not authorized") from exc
            if sqlstate == "55000":
                raise ValueError("approval is no longer pending") from exc
            raise
        if decision == "expired":
            raise ValueError("approval is no longer pending")
        return approval

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
        approval = self.get(approval_id, tenant_id)
        fingerprint = self._fingerprint(intent_fingerprint)
        if approval.status is not ApprovalStatus.APPROVED:
            return approval.status
        if (
            approval.run_id != run_id
            or approval.action != action
            or approval.resource != resource
            or approval.intent_fingerprint != fingerprint
        ):
            raise PermissionError("approval does not bind to this action")
        return approval.status

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
        tenant = self._tenant_uuid(tenant_id)
        if not isinstance(approval_id, UUID) or not isinstance(run_id, UUID):
            raise TypeError("approval_id and run_id must be UUID values")
        normalized_action = self._normalized_text(action, "action")
        normalized_resource = self._normalized_text(resource, "resource", maximum=512)
        fingerprint = self._fingerprint(intent_fingerprint)

        def operation(connection: Any) -> bool:
            row = connection.execute(
                "SELECT platform.consume_approval(%s, %s, %s, %s, %s, %s)",
                (
                    tenant,
                    approval_id,
                    run_id,
                    normalized_action,
                    normalized_resource,
                    fingerprint,
                ),
            ).fetchone()
            if row is None or not isinstance(row[0], bool):
                raise RuntimeError("PostgreSQL approval consumption returned an unexpected result")
            return row[0]

        try:
            consumed = self._transaction(tenant, operation)
        except Exception as exc:
            if getattr(exc, "sqlstate", None) == "42501":
                raise PermissionError("approval does not bind to this action") from exc
            raise
        if not consumed:
            raise PermissionError("approved human review is required")

    def get(self, approval_id: UUID, tenant_id: str) -> ApprovalRequest:
        tenant = self._tenant_uuid(tenant_id)
        if not isinstance(approval_id, UUID):
            raise TypeError("approval_id must be a UUID")

        def operation(connection: Any) -> ApprovalRequest:
            connection.execute(
                "SELECT platform.expire_approval_if_due(%s, %s)",
                (tenant, approval_id),
            )
            return self._load(connection, tenant, approval_id)

        return self._transaction(tenant, operation)
