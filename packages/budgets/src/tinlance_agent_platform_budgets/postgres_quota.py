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
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any
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
        for text_value, name in (
            (self.action, "action"),
            (self.resource, "resource"),
            (self.idempotency_key, "idempotency_key"),
        ):
            if not isinstance(text_value, str):
                raise TypeError(f"{name} must be a string")
            if not text_value or text_value != text_value.strip():
                raise ValueError(f"{name} must be non-empty and normalized")
            if len(text_value) > 256:
                raise ValueError(f"{name} exceeds the maximum length")
            if any(ord(char) < 32 or ord(char) == 127 for char in text_value):
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
            if key not in {
                "cancellation_reason",
                "trace_id",
                "traceparent",
            } and not cls._IDENTIFIER.fullmatch(value):
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
        if "measurement_ref" not in actual.evidence:
            raise ValueError("quota settlement requires a measurement_ref")
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
        if row is None or isinstance(row[0], bool) or not isinstance(row[0], int) or row[0] < 0:
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


if TYPE_CHECKING:
    from .service import BudgetScope


class QuotaReservationReplayError(RuntimeError):
    """An idempotency key was reused for a different reservation intent."""


class QuotaOverrunError(TimeoutError):
    """Measured usage exceeded the reserved quota and was durably recorded."""


@dataclass(frozen=True, slots=True)
class QuotaUsageEstimate:
    """Fail-closed admission estimate derived from a versioned provider price book."""

    tool_calls: int
    token_units: int
    cost_units: float
    provider: str
    model: str
    price_book_version: str
    billing_unit: str = "request"
    metering_source: str = "provider-estimate"

    def __post_init__(self) -> None:
        if (
            isinstance(self.tool_calls, bool)
            or not isinstance(self.tool_calls, int)
            or self.tool_calls < 0
            or isinstance(self.token_units, bool)
            or not isinstance(self.token_units, int)
            or self.token_units < 0
            or isinstance(self.cost_units, bool)
            or not isinstance(self.cost_units, (int, float))
            or not math.isfinite(self.cost_units)
            or self.cost_units < 0
        ):
            raise ValueError("quota estimate dimensions must be finite and non-negative")
        for value, name in (
            (self.provider, "provider"),
            (self.model, "model"),
            (self.price_book_version, "price_book_version"),
            (self.billing_unit, "billing_unit"),
            (self.metering_source, "metering_source"),
        ):
            if not isinstance(value, str) or not PostgresQuotaLedger._IDENTIFIER.fullmatch(value):
                raise ValueError(f"{name} must be a normalized metadata identifier")

    def as_evidence(self) -> dict[str, str]:
        return {
            "provider": self.provider,
            "model": self.model,
            "price_book_version": self.price_book_version,
            "billing_unit": self.billing_unit,
            "metering_source": self.metering_source,
        }


@dataclass(frozen=True, slots=True)
class PostgresBudgetReservation:
    """Execution-bound handle for a durable Platform quota reservation."""

    reservation_id: UUID
    tenant_id: UUID
    organization_id: UUID | None
    scope: Any
    idempotency_key: str
    estimate: QuotaUsageEstimate


class PostgresBudgetGate:
    """Durable execution budget gate backed by the Platform-owned quota ledger.

    A connection factory must return a transaction context manager (for example,
    a psycopg connection). Each reserve/settle/release operation commits in its
    own short transaction. The caller must supply a trusted price-book estimator,
    an authoritative usage meter, and a tenant-scoped organization resolver.
    Missing callbacks or missing measured usage fail closed; no default estimate
    or fabricated settlement is permitted.
    """

    def __init__(
        self,
        connection_factory: Callable[[], Any],
        *,
        estimate_usage: Callable[[Any, int, float], QuotaUsageEstimate],
        measure_usage: Callable[[PostgresBudgetReservation, float], QuotaSettlement],
        resolve_organization: Callable[[Any], UUID | None],
        lease_seconds: int = 900,
    ) -> None:
        if not callable(connection_factory):
            raise TypeError("connection_factory must be callable")
        if not callable(estimate_usage) or not callable(measure_usage):
            raise TypeError("estimate_usage and measure_usage callbacks are required")
        if not callable(resolve_organization):
            raise TypeError("resolve_organization callback is required")
        if (
            isinstance(lease_seconds, bool)
            or not isinstance(lease_seconds, int)
            or not 60 <= lease_seconds <= 3600
        ):
            raise ValueError("lease_seconds must be between 60 and 3600")
        self._connection_factory = connection_factory
        self.estimate_usage = estimate_usage
        self.measure_usage = measure_usage
        self.resolve_organization = resolve_organization
        self.lease_seconds = lease_seconds

    @contextmanager
    def _tenant_ledger(self, tenant_id: UUID) -> Iterator[PostgresQuotaLedger]:
        # set_config(..., true) is transaction-local; never leak tenant context
        # through a pooled connection after the transaction exits.
        with self._connection_factory() as connection:
            connection.execute(
                "SELECT set_config('platform.tenant_id', %s, true)",
                (str(tenant_id),),
            )
            yield PostgresQuotaLedger(connection)

    @staticmethod
    def _tenant_uuid(scope: Any) -> UUID:
        try:
            return UUID(scope.tenant_id)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError("durable quota scope tenant_id must be a UUID") from exc

    @staticmethod
    def _validate_idempotency_key(value: str | None) -> str:
        if (
            not isinstance(value, str)
            or not 16 <= len(value) <= 256
            or value != value.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            raise ValueError("durable quota admission requires a normalized idempotency key")
        return value

    def reserve_new(
        self,
        scope: BudgetScope,
        *,
        tool_calls: int,
        seconds: float,
        idempotency_key: str,
    ) -> PostgresBudgetReservation:
        key = self._validate_idempotency_key(idempotency_key)
        if (
            isinstance(tool_calls, bool)
            or not isinstance(tool_calls, int)
            or tool_calls < 1
            or isinstance(seconds, bool)
            or not isinstance(seconds, (int, float))
            or not math.isfinite(seconds)
            or seconds <= 0
        ):
            raise ValueError("durable quota admission dimensions must be finite and positive")
        tenant_id = self._tenant_uuid(scope)
        estimate = self.estimate_usage(scope, tool_calls, float(seconds))
        if not isinstance(estimate, QuotaUsageEstimate):
            raise TypeError("estimate_usage must return QuotaUsageEstimate")
        if estimate.tool_calls < tool_calls:
            raise ValueError("quota estimate cannot reserve fewer tool calls than requested")
        organization_id = self.resolve_organization(scope)
        if organization_id is not None and not isinstance(organization_id, UUID):
            raise TypeError("resolve_organization must return a UUID or None")
        request = QuotaReservationRequest(
            tenant_id=tenant_id,
            agent_id=scope.agent_id,
            run_id=scope.run_id,
            action=scope.action,
            resource=scope.resource,
            idempotency_key=key,
            concurrency=1,
            tool_calls=estimate.tool_calls,
            token_units=estimate.token_units,
            cost_units=estimate.cost_units,
            organization_id=organization_id,
        )
        try:
            with self._tenant_ledger(tenant_id) as ledger:
                reservation_id = ledger.reserve(request)
        except Exception as exc:
            sqlstate = getattr(exc, "sqlstate", getattr(exc, "pgcode", None))
            if (
                sqlstate == "23505"
                and "idempotency key conflicts with existing reservation" in str(exc).lower()
            ):
                raise QuotaReservationReplayError(
                    "idempotency key conflicts with a different quota reservation intent"
                ) from exc
            raise
        return PostgresBudgetReservation(
            reservation_id,
            tenant_id,
            organization_id,
            scope,
            key,
            estimate,
        )

    def reserve_scoped(
        self,
        scope: BudgetScope,
        *,
        tool_calls: int,
        seconds: float,
        idempotency_key: str | None = None,
    ) -> PostgresBudgetReservation:
        if idempotency_key is None:
            raise ValueError("durable quota admission requires an idempotency key")
        return self.reserve_new(
            scope,
            tool_calls=tool_calls,
            seconds=seconds,
            idempotency_key=idempotency_key,
        )

    def consume(self, reservation: Any, elapsed_seconds: float) -> None:
        if not isinstance(reservation, PostgresBudgetReservation):
            raise TypeError("PostgresBudgetGate requires its own reservation handle")
        if (
            isinstance(elapsed_seconds, bool)
            or not isinstance(elapsed_seconds, (int, float))
            or not math.isfinite(elapsed_seconds)
            or elapsed_seconds < 0
        ):
            raise ValueError("elapsed_seconds must be finite and non-negative")
        measured = self.measure_usage(reservation, float(elapsed_seconds))
        if not isinstance(measured, QuotaSettlement):
            raise TypeError("measure_usage must return QuotaSettlement")
        measured_evidence = self._validate_measured_evidence(measured.evidence)
        measured_price_book = measured_evidence.get("price_book_version")
        if (
            measured_price_book is not None
            and measured_price_book != reservation.estimate.price_book_version
        ):
            raise ValueError("measured usage price book does not match the reserved estimate")
        evidence = reservation.estimate.as_evidence()
        evidence.update(measured_evidence)
        actual = QuotaSettlement(
            measured.tool_calls,
            measured.token_units,
            measured.cost_units,
            evidence,
        )
        with self._tenant_ledger(reservation.tenant_id) as ledger:
            result = ledger.settle(
                tenant_id=reservation.tenant_id,
                reservation_id=reservation.reservation_id,
                actual=actual,
            )
        if result == "overrun":
            raise QuotaOverrunError(
                "measured usage exceeded the reserved quota; the overrun was recorded"
            )

    @staticmethod
    def _validate_measured_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
        safe = PostgresQuotaLedger._validate_evidence(evidence)
        if "measurement_ref" not in safe:
            raise ValueError("measured usage requires a measurement_ref")
        return safe

    def release(self, reservation: Any) -> None:
        if not isinstance(reservation, PostgresBudgetReservation):
            raise TypeError("PostgresBudgetGate requires its own reservation handle")
        with self._tenant_ledger(reservation.tenant_id) as ledger:
            ledger.release(
                tenant_id=reservation.tenant_id,
                reservation_id=reservation.reservation_id,
                reason="cancelled-before-side-effect",
                evidence={
                    "correlation_id": str(reservation.scope.run_id),
                    "metering_source": reservation.estimate.metering_source,
                },
            )

    def renew(self, reservation: PostgresBudgetReservation) -> datetime:
        if not isinstance(reservation, PostgresBudgetReservation):
            raise TypeError("PostgresBudgetGate requires its own reservation handle")
        with self._tenant_ledger(reservation.tenant_id) as ledger:
            renewed_until = ledger.renew(
                tenant_id=reservation.tenant_id,
                reservation_id=reservation.reservation_id,
                lease_seconds=self.lease_seconds,
            )
        return renewed_until

    def request_expired_reconciliation(self, *, tenant_id: UUID, batch_limit: int = 100) -> int:
        with self._tenant_ledger(tenant_id) as ledger:
            return ledger.request_expired_reconciliation(
                tenant_id=tenant_id,
                batch_limit=batch_limit,
            )
