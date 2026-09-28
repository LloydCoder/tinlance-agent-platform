from dataclasses import dataclass
from threading import RLock
from typing import Protocol
from uuid import UUID

from tinlance_agent_platform_contracts import Run


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 60.0

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        if self.base_delay_seconds < 0 or self.max_delay_seconds < 0:
            raise ValueError("retry delays cannot be negative")
        if self.base_delay_seconds > self.max_delay_seconds:
            raise ValueError("base delay cannot exceed maximum delay")

    def delay(self, attempt: int) -> float:
        if attempt < 1 or attempt > self.max_attempts:
            raise ValueError("attempt is outside retry policy")
        delay = self.base_delay_seconds * (2.0 ** (attempt - 1))
        return min(delay, self.max_delay_seconds)


class RunRepository(Protocol):
    def create(self, run: Run, idempotency_key: str) -> Run: ...
    def get(self, tenant_id: str, run_id: UUID) -> Run | None: ...


class IdempotencyStore:
    def __init__(self) -> None:
        self._items: dict[tuple[str, str], UUID] = {}
        self._lock = RLock()

    def claim(self, tenant_id: str, key: str, run_id: UUID) -> bool:
        if not tenant_id or not key:
            raise ValueError("tenant and idempotency key are required")
        if tenant_id != tenant_id.strip() or key != key.strip():
            raise ValueError("tenant and idempotency key must be normalized")
        identity = (tenant_id, key)
        with self._lock:
            existing = self._items.get(identity)
            if existing is not None:
                return existing == run_id
            self._items[identity] = run_id
            return True
