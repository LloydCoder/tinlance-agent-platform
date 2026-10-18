"""Transaction-bound PostgreSQL quota ledger adapter.

The caller owns the transaction and must set platform.tenant_id before use.
Reservation, settlement, the append-only ledger fact, and domain state changes
must commit or roll back together. This adapter never commits or closes a
connection.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any
from uuid import UUID, uuid4


_COST_QUANTUM = Decimal("0.000001")
_MAX_COST_UNITS = Decimal("99999999999999.999999")


def _normalized_cost_units(value: int | float) -> Decimal:
    try:
        normalized = Decimal(str(value)).quantize(_COST_QUANTUM, rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("cost units exceed the supported numeric(20, 6) range") from exc
    if not normalized.is_finite() or normalized < 0 or normalized > _MAX_COST_UNITS:
        raise ValueError("cost units exceed the supported numeric(20, 6) range")
    return normalized


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
            (self.tenant_id, "tenant_id"),
            (self.agent_id, "agent_id"),
            (self.run_id, "run_id"),
        ):
            if not isinstance(value, UUID):
                raise TypeError(f"{name} must be a UUID")
        if self.organization_id is not None and not isinstance(self.organization_id, UUID):
            raise TypeError("organization_id must be a UUID or None")
        if self.reservation_id is not None and not isinstance(self.reservation_id, UUID):
            raise TypeError("reservation_id must be a UUID or None")
        for value, name in (
            (self.action, "action"),
            (self.resource, "resource"),
            (self.idempotency_key, "idempotency_key"),
        ):
            if not isinstance(value, str):
                raise TypeError(f"{name} must be a string")
            if not value or value != value.strip():
                raise ValueError(f"{name} must be non-empty and normalized")
            if len(value) > 256:
                raise ValueError(f"{name} exceeds the maximum length")
            if any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise ValueError(f"{name} must not contain control characters")
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
            or isinstance(self.cost_units, bool)
            or not isinstance(self.cost_units, (int, float))
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

    _EVIDENCE_KEYS = frozenset(
        {
            "provider",
            "model",
            "price_book_version",
            "measurement_ref",
            "source_event_id",
            "cancellation_reason",
            "metering_source",
            "billing_unit",
            "policy_ref",
            "correlation_id",
            "trace_id",
            "traceparent",
            "lease_expires_at",
        }
    )
    _REASON_CODE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
    _IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$")
    _TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
    _TRACEPARENT = re.compile(r"^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$")

    @classmethod
    def _validate_evidence(cls, evidence: dict[str, Any] | None) -> dict[str, Any]:
        if evidence is None:
            return {}
        if not isinstance(evidence, dict):
            raise ValueError("quota evidence must be a JSON object")
        if set(evidence) - cls._EVIDENCE_KEYS:
            raise ValueError("quota evidence contains unsupported fields")
        for key, value in evidence.items():
            if isinstance(value, (dict, list)) or value is None:
                raise ValueError("quota evidence values must be scalar metadata")
            if not isinstance(value, str):
                raise ValueError("quota evidence values must be identifier strings")
            if len(value) > 512:
                raise ValueError("quota evidence string exceeds 512 characters")
            if key == "cancellation_reason" and not cls._REASON_CODE.fullmatch(value):
                raise ValueError("cancellation_reason must be a normalized reason code")
            if key == "trace_id" and not cls._TRACE_ID.fullmatch(value):
                raise ValueError("trace_id must be a lowercase W3C trace identifier")
            if key == "traceparent" and not cls._TRACEPARENT.fullmatch(value):
                raise ValueError("traceparent must be a supported W3C trace context")
            if key not in {"cancellation_reason", "trace_id", "traceparent"} and not cls._IDENTIFIER.fullmatch(
                value
            ):
                raise ValueError(f"{key} must be a normalized metadata identifier")
        encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(encoded.encode("utf-8")) > 4096:
            raise ValueError("quota evidence exceeds 4096 bytes")
        return evidence

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
                _normalized_cost_units(request.cost_units),
            ),
        ).fetchone()
        if row is None or not isinstance(row[0], UUID):
            raise RuntimeError("quota reservation procedure returned an unexpected result")
        # A replay may use a newly generated candidate ID; the database returns
        # the stable ID for the original idempotency key and intent.
        return row[0]

    def settle(
        self,
        *,
        tenant_id: UUID,
        reservation_id: UUID,
        actual: QuotaSettlement,
    ) -> str:
        self._require_transaction()
        if (
            isinstance(actual.tool_calls, bool)
            or not isinstance(actual.tool_calls, int)
            or isinstance(actual.token_units, bool)
            or not isinstance(actual.token_units, int)
            or actual.tool_calls < 0
            or actual.token_units < 0
            or isinstance(actual.cost_units, bool)
            or not isinstance(actual.cost_units, (int, float))
            or not math.isfinite(actual.cost_units)
            or actual.cost_units < 0
        ):
            raise ValueError("actual quota usage must be finite and non-negative")
        evidence = self._validate_evidence(actual.evidence)
        evidence_json = json.dumps(
            evidence,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        row = self._connection.execute(
            "SELECT platform.settle_quota(%s, %s, %s, %s, %s, %s::jsonb)",
            (
                tenant_id,
                reservation_id,
                actual.tool_calls,
                actual.token_units,
                _normalized_cost_units(actual.cost_units),
                evidence_json,
            ),
        ).fetchone()
        if (
            row is None
            or not isinstance(row[0], str)
            or row[0] not in {"settled", "already_settled", "overrun"}
        ):
            raise RuntimeError("quota settlement procedure returned an unexpected result")
        return str(row[0])

    def renew(
        self,
        *,
        tenant_id: UUID,
        reservation_id: UUID,
        lease_seconds: int = 900,
    ) -> datetime:
        """Renew a live reservation lease without changing its quota dimensions."""
        self._require_transaction()
        if (
            isinstance(lease_seconds, bool)
            or not isinstance(lease_seconds, int)
            or not 60 <= lease_seconds <= 3600
        ):
            raise ValueError("lease_seconds must be between 60 and 3600")
        row = self._connection.execute(
            "SELECT platform.renew_quota_reservation(%s, %s, %s)",
            (tenant_id, reservation_id, lease_seconds),
        ).fetchone()
        if row is None or not isinstance(row[0], datetime):
            raise RuntimeError("quota lease renewal returned an unexpected result")
        return row[0]

    def request_expired_reconciliation(
        self,
        *,
        tenant_id: UUID,
        batch_limit: int = 100,
    ) -> int:
        """Mark expired reservations for review; this never releases quota automatically."""
        self._require_transaction()
        if (
            isinstance(batch_limit, bool)
            or not isinstance(batch_limit, int)
            or not 1 <= batch_limit <= 1000
        ):
            raise ValueError("batch_limit must be between 1 and 1000")
        row = self._connection.execute(
            "SELECT platform.request_expired_quota_reconciliation(%s, %s)",
            (tenant_id, batch_limit),
        ).fetchone()
        if (
            row is None
            or isinstance(row[0], bool)
            or not isinstance(row[0], int)
            or row[0] < 0
        ):
            raise RuntimeError("quota reconciliation request returned an unexpected result")
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
        if not isinstance(reason, str) or not self._REASON_CODE.fullmatch(reason):
            raise ValueError("quota release reason must be a normalized reason code")
        safe_evidence = self._validate_evidence(evidence)
        evidence_json = json.dumps(
            safe_evidence, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        row = self._connection.execute(
            "SELECT platform.release_quota(%s, %s, %s, %s::jsonb)",
            (tenant_id, reservation_id, reason, evidence_json),
        ).fetchone()
        if row is None or not isinstance(row[0], bool):
            raise RuntimeError("quota release procedure returned an unexpected result")
        return row[0]
