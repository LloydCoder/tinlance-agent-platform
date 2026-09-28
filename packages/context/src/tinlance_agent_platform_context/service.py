import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class ContextPolicy:
    max_items: int = 32
    max_chars: int = 12000
    allow_untrusted_content: bool = False


@dataclass(frozen=True, slots=True)
class ContextItem:
    source: str
    content: str
    trusted: bool


@dataclass(frozen=True, slots=True)
class MemoryEntry:
    memory_id: UUID
    tenant_id: str
    content: str
    classification: str
    created_at: datetime


class MemoryStore(Protocol):
    def put(self, entry: MemoryEntry) -> MemoryEntry: ...
    def list(self, tenant_id: str, limit: int) -> tuple[MemoryEntry, ...]: ...


class InMemoryMemoryStore:
    def __init__(self) -> None:
        self._items: list[MemoryEntry] = []

    def put(self, entry: MemoryEntry) -> MemoryEntry:
        self._items.append(entry)
        return entry

    def list(self, tenant_id: str, limit: int) -> tuple[MemoryEntry, ...]:
        if limit < 1:
            return ()
        return tuple(e for e in reversed(self._items) if e.tenant_id == tenant_id)[:limit]


class ContextService:
    def __init__(
        self, policy: ContextPolicy | None = None, memory: MemoryStore | None = None
    ) -> None:
        self.policy = policy or ContextPolicy()
        self._memory = memory or InMemoryMemoryStore()

    def remember(
        self, tenant_id: str, content: str, classification: str = "internal"
    ) -> MemoryEntry:
        if (
            not tenant_id
            or not content
            or classification not in {"public", "internal", "sensitive"}
        ):
            raise ValueError("invalid memory entry")
        return self._memory.put(
            MemoryEntry(
                uuid4(),
                tenant_id,
                self.redact_sensitive(content),
                classification,
                datetime.now(UTC),
            )
        )

    def recall(self, tenant_id: str, limit: int = 16) -> tuple[MemoryEntry, ...]:
        if not tenant_id:
            raise ValueError("tenant is required")
        return self._memory.list(tenant_id, limit)

    def build(self, tenant_id: str, items: list[ContextItem], include_memory: bool = True) -> str:
        if not tenant_id:
            raise ValueError("tenant is required")
        selected: list[str] = []
        if include_memory:
            for memory in self.recall(tenant_id, self.policy.max_items):
                selected.append(
                    "<memory source=platform-memory "
                    f"classification={memory.classification}>\n"
                    f"{memory.content}\n</memory>"
                )
        for item in items:
            if not item.trusted and not self.policy.allow_untrusted_content:
                continue
            marker = "trusted" if item.trusted else "untrusted"
            selected.append(f"<{marker} source={item.source}>\n{item.content}\n</{marker}>")
            if len(selected) >= self.policy.max_items:
                break
        return "\n".join(selected)[: self.policy.max_chars]

    def redact_sensitive(self, text: str) -> str:
        pattern = r"(?i)(SECRET|API_KEY|PASSWORD|TOKEN|AUTHORIZATION)\\s*[=:]\\s*[^\\s\\n]+"
        return re.sub(pattern, lambda match: match.group(1) + "=[REDACTED]", text)
