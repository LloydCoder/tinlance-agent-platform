from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from tinlance_agent_platform_contracts import Run


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 60.0

    def delay(self, attempt: int) -> float:
        if attempt < 1 or attempt > self.max_attempts:
            raise ValueError("attempt is outside retry policy")
        return min(self.base_delay_seconds * (2 ** (attempt - 1)), self.max_delay_seconds)


class RunRepository(Protocol):
    def create(self, run: Run, idempotency_key: str) -> Run: ...
    def get(self, tenant_id: str, run_id: UUID) -> Run | None: ...


class IdempotencyStore:
    def __init__(self) -> None:
        self._items: dict[tuple[str, str], UUID] = {}

    def claim(self, tenant_id: str, key: str, run_id: UUID) -> bool:
        if not tenant_id or not key:
            raise ValueError("tenant and idempotency key are required")
        identity = (tenant_id, key)
        existing = self._items.get(identity)
        if existing is not None:
            return existing == run_id
        self._items[identity] = run_id
        return True
