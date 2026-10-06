"""Atomic capacity and tenant economic governance contracts.

These reference controls are admission/settlement guards, not authorization.
Production deployments must back the same state machine with a transactional
shared store so concurrent workers cannot oversubscribe a tenant.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock


@dataclass(frozen=True, slots=True)
class CapacityEnvelope:
    minimum_throughput_per_minute: float
    maximum_p95_ms: float
    maximum_p99_ms: float
    maximum_concurrency: int

    def __post_init__(self) -> None:
        if (
            self.minimum_throughput_per_minute < 0
            or self.maximum_p95_ms < 0
            or self.maximum_p99_ms < 0
            or self.maximum_concurrency < 1
        ):
            raise ValueError("capacity envelope values are invalid")
        if self.maximum_p95_ms > self.maximum_p99_ms:
            raise ValueError("p95 latency ceiling cannot exceed p99 latency ceiling")


@dataclass(frozen=True, slots=True)
class CapacityObservation:
    throughput_per_minute: float
    p95_ms: float
    p99_ms: float
    concurrency: int

    def __post_init__(self) -> None:
        if (
            self.throughput_per_minute < 0
            or self.p95_ms < 0
            or self.p99_ms < 0
            or self.concurrency < 0
            or self.p95_ms > self.p99_ms
        ):
            raise ValueError("capacity observation values are invalid")

    @property
    def within(self) -> bool:
        return True


@dataclass(frozen=True, slots=True)
class CapacityGate:
    envelope: CapacityEnvelope
    observation: CapacityObservation
    evidence_ref: str

    def __post_init__(self) -> None:
        if not self.evidence_ref.strip():
            raise ValueError("capacity evidence is required")

    def evaluate(self) -> None:
        if self.observation.throughput_per_minute < self.envelope.minimum_throughput_per_minute:
            raise RuntimeError("capacity throughput target failed")
        if self.observation.p95_ms > self.envelope.maximum_p95_ms:
            raise RuntimeError("capacity p95 target failed")
        if self.observation.p99_ms > self.envelope.maximum_p99_ms:
            raise RuntimeError("capacity p99 target failed")
        if self.observation.concurrency > self.envelope.maximum_concurrency:
            raise RuntimeError("capacity concurrency target failed")


@dataclass(frozen=True, slots=True)
class TenantQuota:
    max_concurrency: int
    max_tool_calls: int
    max_token_units: int
    max_cost_units: float

    def __post_init__(self) -> None:
        if (
            self.max_concurrency < 1
            or self.max_tool_calls < 0
            or self.max_token_units < 0
            or self.max_cost_units < 0
        ):
            raise ValueError("tenant quota values are invalid")

    def admits(
        self,
        *,
        concurrency: int,
        tool_calls: int,
        token_units: int,
        cost_units: float,
    ) -> bool:
        if (
            concurrency < 0
            or tool_calls < 0
            or token_units < 0
            or cost_units < 0
        ):
            return False
        return (
            concurrency <= self.max_concurrency
            and tool_calls <= self.max_tool_calls
            and token_units <= self.max_token_units
            and cost_units <= self.max_cost_units
        )


@dataclass(frozen=True, slots=True)
class TenantReservation:
    reservation_id: str
    tenant_id: str
    agent_id: str
    run_id: str
    action: str
    resource: str
    concurrency: int
    tool_calls: int
    token_units: int
    cost_units: float


class TenantQuotaService:
    """Atomic in-process reference quota ledger.

    Reservation is the admission decision. Settlement consumes the reservation;
    release returns reserved capacity. The reservation is immutable and bound to
    tenant/agent/run/action/resource so it cannot be transferred across scopes.
    """

    def __init__(self, quota: TenantQuota) -> None:
        self._quota = quota
        self._lock = RLock()
        self._reservations: dict[str, TenantReservation] = {}
        self._consumed = (0, 0, 0, 0.0)

    @property
    def quota(self) -> TenantQuota:
        return self._quota

    def reserve(
        self,
        *,
        reservation_id: str,
        tenant_id: str,
        agent_id: str,
        run_id: str,
        action: str,
        resource: str,
        concurrency: int = 1,
        tool_calls: int = 0,
        token_units: int = 0,
        cost_units: float = 0.0,
    ) -> TenantReservation:
        fields = (reservation_id, tenant_id, agent_id, run_id, action, resource)
        if any(not value or value != value.strip() for value in fields):
            raise ValueError("reservation scope fields are required and normalized")
        if (
            concurrency < 1
            or tool_calls < 0
            or token_units < 0
            or cost_units < 0
        ):
            raise ValueError("reservation dimensions are invalid")
        with self._lock:
            reserved = tuple(
                sum(getattr(item, name) for item in self._reservations.values())
                for name in ("concurrency", "tool_calls", "token_units", "cost_units")
            )
            totals = tuple(
                consumed + pending + requested
                for consumed, pending, requested in zip(
                    self._consumed,
                    reserved,
                    (concurrency, tool_calls, token_units, cost_units),
                    strict=True,
                )
            )
            if not self._quota.admits(
                concurrency=totals[0],
                tool_calls=totals[1],
                token_units=totals[2],
                cost_units=totals[3],
            ):
                raise TimeoutError("tenant resource quota exhausted")
            item = TenantReservation(
                reservation_id,
                tenant_id,
                agent_id,
                run_id,
                action,
                resource,
                concurrency,
                tool_calls,
                token_units,
                cost_units,
            )
            if reservation_id in self._reservations:
                existing = self._reservations[reservation_id]
                if existing != item:
                    raise ValueError("reservation ID conflicts with a different scope")
                return existing
            self._reservations[reservation_id] = item
            return item

    def settle(self, reservation: TenantReservation) -> None:
        with self._lock:
            current = self._reservations.get(reservation.reservation_id)
            if current != reservation:
                raise KeyError("tenant reservation does not exist")
            self._consumed = tuple(
                left + right
                for left, right in zip(
                    self._consumed,
                    (
                        reservation.concurrency,
                        reservation.tool_calls,
                        reservation.token_units,
                        reservation.cost_units,
                    ),
                    strict=True,
                )
            )
            del self._reservations[reservation.reservation_id]

    def release(self, reservation: TenantReservation) -> None:
        with self._lock:
            current = self._reservations.get(reservation.reservation_id)
            if current is not None and current != reservation:
                raise KeyError("tenant reservation scope mismatch")
            self._reservations.pop(reservation.reservation_id, None)

    def consumed(self) -> tuple[int, int, int, float]:
        with self._lock:
            return self._consumed
