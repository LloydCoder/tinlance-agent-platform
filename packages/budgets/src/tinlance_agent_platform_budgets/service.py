from dataclasses import dataclass, replace
from threading import RLock
from uuid import UUID, uuid4

from tinlance_agent_platform_contracts import Budget

from .quota import TenantQuotaService, TenantReservation


@dataclass(frozen=True, slots=True)
class BudgetScope:
    tenant_id: str
    agent_id: UUID
    run_id: UUID
    action: str
    resource: str

    def __post_init__(self) -> None:
        values = (self.tenant_id, self.action, self.resource)
        if any(not value or value != value.strip() for value in values):
            raise ValueError("budget scope fields are required and normalized")
        if any(len(value) > 4096 for value in values):
            raise ValueError("budget scope fields exceed safety limits")
        if not isinstance(self.agent_id, UUID) or not isinstance(self.run_id, UUID):
            raise TypeError("budget scope identifiers must be UUIDs")


@dataclass(frozen=True, slots=True)
class BudgetReservation:
    reservation_id: UUID
    tenant_id: str
    run_id: UUID
    tool_calls: int
    seconds: float
    scope: BudgetScope


class BudgetService:
    """Race-safe run budget plus exact execution-intent scope binding."""

    def __init__(
        self,
        budget: Budget,
        *,
        tenant_quota: TenantQuotaService | None = None,
    ) -> None:
        self._budget = budget
        self._tenant_quota = tenant_quota
        self._lock = RLock()
        self._reservations: dict[UUID, BudgetReservation] = {}

    @property
    def budget(self) -> Budget:
        with self._lock:
            return self._budget

    def reserve_scoped(
        self,
        scope: BudgetScope,
        *,
        tool_calls: int,
        seconds: float,
        reservation_id: UUID | None = None,
    ) -> BudgetReservation:
        if scope.tenant_id != self._budget.tenant_id or scope.run_id != self._budget.run_id:
            raise PermissionError("budget is owned by another tenant or run")
        if tool_calls < 0 or seconds < 0:
            raise ValueError("reservation dimensions cannot be negative")
        with self._lock:
            rid = reservation_id or uuid4()
            existing = self._reservations.get(rid)
            candidate = BudgetReservation(
                rid, scope.tenant_id, scope.run_id, tool_calls, seconds, scope
            )
            if existing is not None:
                if existing != candidate:
                    raise ValueError("budget reservation ID conflicts with a different scope")
                return existing
            reserved_calls = sum(item.tool_calls for item in self._reservations.values())
            reserved_seconds = sum(item.seconds for item in self._reservations.values())
            if (
                self._budget.consumed_tool_calls + reserved_calls + tool_calls
                > self._budget.max_tool_calls
                or self._budget.elapsed_seconds + reserved_seconds + seconds
                > self._budget.max_seconds
            ):
                raise TimeoutError("budget exhausted")
            if self._tenant_quota is not None:
                self._tenant_quota.reserve(
                    reservation_id=str(rid),
                    tenant_id=scope.tenant_id,
                    agent_id=str(scope.agent_id),
                    run_id=str(scope.run_id),
                    action=scope.action,
                    resource=scope.resource,
                    concurrency=1,
                    tool_calls=tool_calls,
                )
            self._reservations[rid] = candidate
            return candidate

    def reserve(
        self,
        tenant_id: str,
        run_id: UUID,
        *,
        tool_calls: int = 1,
        seconds: float = 0.0,
    ) -> BudgetReservation:
        scope = BudgetScope(
            tenant_id,
            UUID(int=0),
            run_id,
            "legacy",
            "legacy",
        )
        return self.reserve_scoped(scope, tool_calls=tool_calls, seconds=seconds)

    def consume(self, reservation: BudgetReservation, elapsed_seconds: float) -> None:
        if elapsed_seconds < 0:
            raise ValueError("elapsed time cannot be negative")
        with self._lock:
            current = self._reservations.get(reservation.reservation_id)
            if current != reservation:
                raise KeyError("budget reservation does not exist")
            if elapsed_seconds > current.seconds:
                raise TimeoutError("execution exceeded reserved runtime budget")
            self._budget = replace(
                self._budget,
                consumed_tool_calls=self._budget.consumed_tool_calls + current.tool_calls,
                elapsed_seconds=self._budget.elapsed_seconds + elapsed_seconds,
            )
            if self._tenant_quota is not None:
                self._tenant_quota.settle(
                    TenantReservation(
                        str(current.reservation_id),
                        current.scope.tenant_id,
                        str(current.scope.agent_id),
                        str(current.scope.run_id),
                        current.scope.action,
                        current.scope.resource,
                        1,
                        current.tool_calls,
                        0,
                        0.0,
                    )
                )
            del self._reservations[reservation.reservation_id]

    def release(self, reservation: BudgetReservation) -> None:
        with self._lock:
            current = self._reservations.get(reservation.reservation_id)
            if current is not None and current != reservation:
                raise KeyError("budget reservation scope mismatch")
            self._reservations.pop(reservation.reservation_id, None)
            if current is not None and self._tenant_quota is not None:
                self._tenant_quota.release(
                    TenantReservation(
                        str(current.reservation_id),
                        current.scope.tenant_id,
                        str(current.scope.agent_id),
                        str(current.scope.run_id),
                        current.scope.action,
                        current.scope.resource,
                        1,
                        current.tool_calls,
                        0,
                        0.0,
                    )
                )

    def consume_turn(self, elapsed_seconds: float) -> None:
        if elapsed_seconds < 0:
            raise ValueError("elapsed time cannot be negative")
        with self._lock:
            if self._budget.consumed_turns + 1 > self._budget.max_turns:
                raise TimeoutError("maximum turns exceeded")
            if self._budget.elapsed_seconds + elapsed_seconds > self._budget.max_seconds:
                raise TimeoutError("maximum runtime exceeded")
            self._budget = replace(
                self._budget,
                consumed_turns=self._budget.consumed_turns + 1,
                elapsed_seconds=self._budget.elapsed_seconds + elapsed_seconds,
            )

    def consume_tool_call(self) -> None:
        with self._lock:
            if self._budget.consumed_tool_calls + 1 > self._budget.max_tool_calls:
                raise TimeoutError("maximum tool calls exceeded")
            self._budget = replace(
                self._budget,
                consumed_tool_calls=self._budget.consumed_tool_calls + 1,
            )
