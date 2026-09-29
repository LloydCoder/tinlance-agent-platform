from dataclasses import dataclass, replace
from threading import RLock
from uuid import UUID, uuid4

from tinlance_agent_platform_contracts import Budget


@dataclass(frozen=True, slots=True)
class BudgetReservation:
    reservation_id: UUID
    tenant_id: str
    run_id: UUID
    tool_calls: int
    seconds: float


class BudgetService:
    """Race-safe budget authority with reservation/commit/release semantics."""

    def __init__(self, budget: Budget) -> None:
        self._budget = budget
        self._lock = RLock()
        self._reservations: dict[UUID, BudgetReservation] = {}

    @property
    def budget(self) -> Budget:
        with self._lock:
            return self._budget

    def reserve(
        self,
        tenant_id: str,
        run_id: UUID,
        *,
        tool_calls: int = 1,
        seconds: float = 0.0,
    ) -> BudgetReservation:
        if tool_calls < 0 or seconds < 0:
            raise ValueError("reservation dimensions cannot be negative")
        with self._lock:
            if self._budget.tenant_id != tenant_id or self._budget.run_id != run_id:
                raise PermissionError("budget is owned by another tenant or run")
            reserved_calls = sum(item.tool_calls for item in self._reservations.values())
            reserved_seconds = sum(item.seconds for item in self._reservations.values())
            if (
                self._budget.consumed_tool_calls + reserved_calls + tool_calls
                > self._budget.max_tool_calls
                or self._budget.elapsed_seconds + reserved_seconds + seconds
                > self._budget.max_seconds
            ):
                raise TimeoutError("budget exhausted")
            item = BudgetReservation(uuid4(), tenant_id, run_id, tool_calls, seconds)
            self._reservations[item.reservation_id] = item
            return item

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
            del self._reservations[reservation.reservation_id]

    def release(self, reservation: BudgetReservation) -> None:
        with self._lock:
            self._reservations.pop(reservation.reservation_id, None)

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
