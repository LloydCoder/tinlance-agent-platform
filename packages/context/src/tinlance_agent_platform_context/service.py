from dataclasses import dataclass
from datetime import UTC, datetime
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


class ContextService:
    def __init__(self, policy: ContextPolicy | None = None) -> None:
        self.policy = policy or ContextPolicy()
        self._memory: list[MemoryEntry] = []

    def remember(
        self, tenant_id: str, content: str, classification: str = "internal"
    ) -> MemoryEntry:
        allowed = {"public", "internal", "sensitive"}
        if not tenant_id or not content or classification not in allowed:
            raise ValueError("invalid memory entry")
        entry = MemoryEntry(uuid4(), tenant_id, content, classification, datetime.now(UTC))
        self._memory.append(entry)
        return entry

    def build(self, tenant_id: str, items: list[ContextItem]) -> str:
        selected: list[str] = []
        for item in items:
            if not item.trusted and not self.policy.allow_untrusted_content:
                continue
            selected.append(f"[{item.source}] {item.content}")
            if len(selected) >= self.policy.max_items:
                break
        result = "\n".join(selected)
        return result[: self.policy.max_chars]

    def redact_sensitive(self, text: str) -> str:
        for marker in ("SECRET=", "API_KEY=", "PASSWORD="):
            while marker in text:
                start = text.index(marker)
                end = text.find("\n", start)
                if end < 0:
                    end = len(text)
                text = text[:start] + marker + "[REDACTED]" + text[end:]
        return text
