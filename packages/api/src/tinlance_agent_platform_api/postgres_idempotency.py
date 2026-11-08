"""Durable PostgreSQL idempotency guard for consequential Platform API operations."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from contextlib import suppress
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from .service import APIRequest, APIResponse, IdempotencyConflictError

_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")


class IdempotencyInProgressError(IdempotencyConflictError):
    """The same guarded operation is currently executing on another worker."""

    code = "idempotency_in_progress"
    retryable = True


class IdempotencyOutcomeUnknownError(IdempotencyConflictError):
    """The prior operation may have reached its side effect; automatic replay is unsafe."""

    code = "idempotency_outcome_unknown"


class PostgresAPIIdempotencyStore:
    """Reserve, execute once, and persist a response under tenant-scoped PostgreSQL RLS.

    Reservations are committed before invoking the handler so database locks are never
    held across network calls. An expired or interrupted reservation becomes
    outcome_unknown and is deliberately not reclaimed for automatic execution.
    """

    def __init__(
        self,
        *,
        connection_factory: Callable[[], Any],
        lease_seconds: int = 300,
        retention_days: int = 30,
    ) -> None:
        if not 30 <= lease_seconds <= 3600:
            raise ValueError("idempotency lease must be between 30 and 3600 seconds")
        if not 1 <= retention_days <= 365:
            raise ValueError("idempotency retention must be between 1 and 365 days")
        self._connection_factory = connection_factory
        self._lease_seconds = lease_seconds
        self._retention_days = retention_days

    @staticmethod
    def _tenant_uuid(tenant_id: str) -> UUID:
        try:
            return UUID(tenant_id)
        except (ValueError, AttributeError) as exc:
            raise ValueError("PostgreSQL idempotency tenant ID must be a UUID") from exc

    @staticmethod
    def _key(request: APIRequest) -> str:
        key = request.idempotency_key or request.request_id
        if (
            not isinstance(key, str)
            or not 1 <= len(key) <= 256
            or not key.isascii()
            or any(ord(character) < 33 or ord(character) > 126 for character in key)
        ):
            raise ValueError("idempotency key must be normalized visible ASCII")
        return key

    def _transaction(self, tenant_id: UUID, operation: Callable[[Any], Any]) -> Any:
        connection = self._connection_factory()
        try:
            if getattr(connection, "autocommit", False):
                raise RuntimeError("PostgresAPIIdempotencyStore requires explicit transactions")
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

    def execute_once(
        self,
        request: APIRequest,
        fingerprint: str,
        operation: Callable[[], APIResponse],
    ) -> APIResponse:
        tenant_uuid = self._tenant_uuid(request.tenant_id)
        key = self._key(request)
        if not request.subject_id or request.subject_id != request.subject_id.strip():
            raise ValueError("idempotency subject must be normalized")
        if not request.operation or request.operation != request.operation.strip():
            raise ValueError("idempotency operation must be normalized")
        if not _FINGERPRINT.fullmatch(fingerprint):
            raise ValueError("idempotency fingerprint must be a SHA-256 hex digest")

        state, cached = self._reserve(
            tenant_uuid=tenant_uuid,
            subject_id=request.subject_id,
            operation=request.operation,
            idempotency_key=key,
            fingerprint=fingerprint,
        )
        if state == "completed":
            if cached is None:
                raise RuntimeError("completed idempotency record has no response")
            return deepcopy(cached)
        if state == "in_progress":
            raise IdempotencyInProgressError("the idempotent operation is already in progress")
        if state == "outcome_unknown":
            raise IdempotencyOutcomeUnknownError(
                "the prior operation outcome is unknown; automatic replay is unsafe"
            )
        if state != "reserved":
            raise RuntimeError("PostgreSQL idempotency reservation returned an unknown state")

        try:
            response = operation()
            if not isinstance(response, APIResponse):
                raise TypeError("guarded API handler must return APIResponse")
        except BaseException:
            with suppress(Exception):
                self._mark_outcome_unknown(
                    tenant_uuid=tenant_uuid,
                    subject_id=request.subject_id,
                    idempotency_key=key,
                    fingerprint=fingerprint,
                )
            raise

        self._complete(
            tenant_uuid=tenant_uuid,
            subject_id=request.subject_id,
            idempotency_key=key,
            fingerprint=fingerprint,
            response=response,
        )
        return deepcopy(response)

    def _reserve(
        self,
        *,
        tenant_uuid: UUID,
        subject_id: str,
        operation: str,
        idempotency_key: str,
        fingerprint: str,
    ) -> tuple[str, APIResponse | None]:
        def reserve(connection: Any) -> tuple[str, APIResponse | None]:
            inserted = connection.execute(
                """
                INSERT INTO platform.api_idempotency_records (
                    tenant_id, subject_id, idempotency_key, operation,
                    request_fingerprint, status, lease_expires_at, expires_at
                ) VALUES (
                    %s, %s, %s, %s, %s, 'processing',
                    now() + (%s * interval '1 second'),
                    now() + (%s * interval '1 day')
                )
                ON CONFLICT (tenant_id, subject_id, idempotency_key) DO NOTHING
                RETURNING idempotency_key
                """,
                (
                    tenant_uuid,
                    subject_id,
                    idempotency_key,
                    operation,
                    fingerprint,
                    self._lease_seconds,
                    self._retention_days,
                ),
            ).fetchone()
            if inserted is not None:
                return "reserved", None

            row = connection.execute(
                """
                SELECT request_fingerprint, operation, status, response_status,
                       response_payload, lease_expires_at
                FROM platform.api_idempotency_records
                WHERE tenant_id = %s AND subject_id = %s AND idempotency_key = %s
                FOR UPDATE
                """,
                (tenant_uuid, subject_id, idempotency_key),
            ).fetchone()
            if row is None:
                raise RuntimeError("idempotency conflict row disappeared during reservation")
            if row[0] != fingerprint or row[1] != operation:
                raise IdempotencyConflictError(
                    "idempotency key was reused for a different consequential request"
                )
            status = row[2]
            if status == "completed":
                payload = row[4]
                if isinstance(payload, str):
                    payload = json.loads(payload)
                if not isinstance(row[3], str) or not isinstance(payload, dict):
                    raise RuntimeError("completed idempotency response is malformed")
                return "completed", APIResponse(row[3], payload)
            if status == "processing":
                lease_expires_at = row[5]
                if lease_expires_at is not None and lease_expires_at <= datetime.now(UTC):
                    connection.execute(
                        """
                        UPDATE platform.api_idempotency_records
                        SET status = 'outcome_unknown', lease_expires_at = NULL,
                            updated_at = now()
                        WHERE tenant_id = %s AND subject_id = %s
                          AND idempotency_key = %s AND status = 'processing'
                        """,
                        (tenant_uuid, subject_id, idempotency_key),
                    )
                    return "outcome_unknown", None
                return "in_progress", None
            if status == "outcome_unknown":
                return "outcome_unknown", None
            raise RuntimeError("idempotency record has an unsupported state")

        return self._transaction(tenant_uuid, reserve)

    def _complete(
        self,
        *,
        tenant_uuid: UUID,
        subject_id: str,
        idempotency_key: str,
        fingerprint: str,
        response: APIResponse,
    ) -> None:
        if not response.status or response.status != response.status.strip():
            raise ValueError("API response status must be normalized")
        payload = json.dumps(
            response.payload,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )

        def complete(connection: Any) -> None:
            row = connection.execute(
                """
                UPDATE platform.api_idempotency_records
                SET status = 'completed', response_status = %s,
                    response_payload = %s::jsonb, lease_expires_at = NULL,
                    updated_at = now(), completed_at = now()
                WHERE tenant_id = %s AND subject_id = %s AND idempotency_key = %s
                  AND request_fingerprint = %s AND status = 'processing'
                RETURNING idempotency_key
                """,
                (response.status, payload, tenant_uuid, subject_id, idempotency_key, fingerprint),
            ).fetchone()
            if row is None:
                raise RuntimeError("durable idempotency completion lost its reservation")

        self._transaction(tenant_uuid, complete)

    def _mark_outcome_unknown(
        self,
        *,
        tenant_uuid: UUID,
        subject_id: str,
        idempotency_key: str,
        fingerprint: str,
    ) -> None:
        def mark(connection: Any) -> None:
            connection.execute(
                """
                UPDATE platform.api_idempotency_records
                SET status = 'outcome_unknown', lease_expires_at = NULL, updated_at = now()
                WHERE tenant_id = %s AND subject_id = %s AND idempotency_key = %s
                  AND request_fingerprint = %s AND status = 'processing'
                """,
                (tenant_uuid, subject_id, idempotency_key, fingerprint),
            )

        self._transaction(tenant_uuid, mark)
