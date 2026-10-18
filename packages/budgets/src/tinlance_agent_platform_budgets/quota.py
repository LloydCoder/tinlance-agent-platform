"""Atomic tenant resource quota reservations."""

from __future__ import annotations

import math
from dataclasses import dataclass
from threading import RLock


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
    """Reference atomic quota ledger.

    Admission is a reservation decision. Settlement consumes reserved capacity;
    release returns it. Reservations are immutable and scope-bound.
    """

    def __init__(
        self,
        *,
        max_concurrency: int,
        max_tool_calls: int,
        max_token_units: int,
        max_cost_units: float,
    ) -> None:
        if (
            isinstance(max_concurrency, bool)
            or not isinstance(max_concurrency, int)
            or isinstance(max_tool_calls, bool)
            or not isinstance(max_tool_calls, int)
            or isinstance(max_token_units, bool)
            or not isinstance(max_token_units, int)
            or isinstance(max_cost_units, bool)
            or not isinstance(max_cost_units, (int, float))
            or not math.isfinite(max_cost_units)
            or max_concurrency < 1
            or max_tool_calls < 0
            or max_token_units < 0
            or max_cost_units < 0
        ):
            raise ValueError("tenant quota values are invalid")
        self._limits = (
            max_concurrency,
            max_tool_calls,
            max_token_units,
            max_cost_units,
        )
        self._consumed = (0, 0, 0, 0.0)
        self._reservations: dict[str, TenantReservation] = {}
        self._lock = RLock()

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
        values = (reservation_id, tenant_id, agent_id, run_id, action, resource)
        if any(not isinstance(value, str) for value in values):
            raise TypeError("quota reservation scope fields must be strings")
        if any(not value or value != value.strip() for value in values):
            raise ValueError("quota reservation scope is required and normalized")
        if any(len(value) > 256 for value in values):
            raise ValueError("quota reservation scope exceeds safety limits")
        if any(ord(char) < 32 or ord(char) == 127 for value in values for char in value):
            raise ValueError("quota reservation scope must not contain control characters")
        if (
            any(
                isinstance(value, bool) or not isinstance(value, int)
                for value in (concurrency, tool_calls, token_units)
            )
            or isinstance(cost_units, bool)
            or not isinstance(cost_units, (int, float))
            or not math.isfinite(cost_units)
            or concurrency < 1
            or tool_calls < 0
            or token_units < 0
            or cost_units < 0
        ):
            raise ValueError("quota reservation dimensions are invalid")
        candidate = TenantReservation(
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
        with self._lock:
            existing = self._reservations.get(reservation_id)
            if existing is not None:
                if existing != candidate:
                    raise ValueError("quota reservation ID conflicts with scope")
                return existing
            pending = tuple(
                sum(getattr(item, field) for item in self._reservations.values())
                for field in ("concurrency", "tool_calls", "token_units", "cost_units")
            )
            totals = tuple(
                consumed + reserved + requested
                for consumed, reserved, requested in zip(
                    self._consumed,
                    pending,
                    (concurrency, tool_calls, token_units, cost_units),
                    strict=True,
                )
            )
            if any(total > limit for total, limit in zip(totals, self._limits, strict=True)):
                raise TimeoutError("tenant resource quota exhausted")
            self._reservations[reservation_id] = candidate
            return candidate

    def settle(self, reservation: TenantReservation) -> None:
        with self._lock:
            current = self._reservations.get(reservation.reservation_id)
            if current != reservation:
                raise KeyError("quota reservation does not exist")
            # Concurrency is an in-flight gauge, not cumulative consumption.
            # Removing the reservation below releases its concurrency atomically.
            self._consumed = (
                self._consumed[0],
                self._consumed[1] + reservation.tool_calls,
                self._consumed[2] + reservation.token_units,
                self._consumed[3] + reservation.cost_units,
            )
            del self._reservations[reservation.reservation_id]

    def release(self, reservation: TenantReservation) -> None:
        with self._lock:
            current = self._reservations.get(reservation.reservation_id)
            if current is not None and current != reservation:
                raise KeyError("quota reservation scope mismatch")
            self._reservations.pop(reservation.reservation_id, None)

    @property
    def consumed(self) -> tuple[int, int, int, float]:
        with self._lock:
            return self._consumed
