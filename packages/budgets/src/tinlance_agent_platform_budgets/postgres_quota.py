"""Transaction-bound PostgreSQL quota ledger adapter.

The caller owns the transaction and must set platform.tenant_id before use.
Reservation, settlement, the append-only ledger fact, and domain state changes
must commit or roll back together. This adapter never commits or closes a
connection.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class QuotaReservationRequest:
    tenant_id: UUID
    agent_id: UUID
    run_id: UUID
    action: str
    resource: str
    idempotency_key: str
    concurrency: int = 1
    tool_calls: int = 0
    token_units: int = 0
    cost_units: float = 0.0
    organization_id: UUID | None = None
    reservation_id: UUID | None = None

    def __post_init__(self) -> None:
        for value, name in (
            (self.action, "action"),
            (self.resource, "resource"),
            (self.idempotency_key, "idempotency_key"),
        ):
            if not value or value != value.strip():
                raise ValueError(f"{name} must be non-empty and normalized")
        if not 16 <= len(self.idempotency_key) <= 256:
            raise ValueError("idempotency_key must contain 16 to 256 characters")
        if (
            isinstance(self.concurrency, bool)
            or not isinstance(self.concurrency, int)
            or isinstance(self.tool_calls, bool)
            or not isinstance(self.tool_calls, int)
            or isinstance(self.token_units, bool)
            or not isinstance(self.token_units, int)
            or self.concurrency < 1
            or self.tool_calls < 0
            or self.token_units < 0
            or not math.isfinite(self.cost_units)
            or self.cost_units < 0
        ):
            raise ValueError("quota reservation dimensions must be finite and valid")


@dataclass(frozen=True, slots=True)
class QuotaSettlement:
    tool_calls: int
    token_units: int
    cost_units: float
    evidence: dict[str, Any]


class PostgresQuotaLedger:
    """Calls the migration-owned transactional quota procedures."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def _require_transaction(self) -> None:
        if getattr(self._connection, "autocommit", False):
            info = getattr(self._connection, "info", None)
            transaction_status = getattr(info, "transaction_status", None)
            if transaction_status is None or int(transaction_status) == 0:
                raise RuntimeError("quota ledger requires a caller-owned active transaction")

    def reserve(self, request: QuotaReservationRequest) -> UUID:
        self._require_transaction()
        reservation_id = request.reservation_id or uuid4()
        row = self._connection.execute(
            "SELECT platform.reserve_quota(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                reservation_id,
                request.tenant_id,
                request.organization_id,
                request.agent_id,
                request.run_id,
                request.action,
                request.resource,
                request.idempotency_key,
                request.concurrency,
                request.tool_calls,
                request.token_units,
                request.cost_units,
            ),
        ).fetchone()
        if row is None or row[0] != reservation_id:
            raise RuntimeError("quota reservation procedure returned an unexpected result")
        return reservation_id

    def settle(
        self,
        *,
        tenant_id: UUID,
        reservation_id: UUID,
        actual: QuotaSettlement,
    ) -> bool:
        self._require_transaction()
        if (
            isinstance(actual.tool_calls, bool)
            or not isinstance(actual.tool_calls, int)
            or isinstance(actual.token_units, bool)
            or not isinstance(actual.token_units, int)
            or actual.tool_calls < 0
            or actual.token_units < 0
            or not math.isfinite(actual.cost_units)
            or actual.cost_units < 0
        ):
            raise ValueError("actual quota usage must be finite and non-negative")
        evidence_json = json.dumps(actual.evidence, sort_keys=True, separators=(",", ":"), allow_nan=False)
        row = self._connection.execute(
            "SELECT platform.settle_quota(%s, %s, %s, %s, %s, %s::jsonb)",
            (
                tenant_id,
                reservation_id,
                actual.tool_calls,
                actual.token_units,
                actual.cost_units,
                evidence_json,
            ),
        ).fetchone()
        if row is None or not isinstance(row[0], bool):
            raise RuntimeError("quota settlement procedure returned an unexpected result")
        return row[0]

    def release(
        self,
        *,
        tenant_id: UUID,
        reservation_id: UUID,
        reason: str,
        evidence: dict[str, Any] | None = None,
    ) -> bool:
        self._require_transaction()
        if not reason or reason != reason.strip():
            raise ValueError("quota release reason is required and normalized")
        evidence_json = json.dumps(
            evidence or {}, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        row = self._connection.execute(
            "SELECT platform.release_quota(%s, %s, %s, %s::jsonb)",
            (tenant_id, reservation_id, reason, evidence_json),
        ).fetchone()
        if row is None or not isinstance(row[0], bool):
            raise RuntimeError("quota release procedure returned an unexpected result")
        return row[0]
