import re
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
        redacted = self.redact_sensitive(content)
        entry = MemoryEntry(uuid4(), tenant_id, redacted, classification, datetime.now(UTC))
        self._memory.append(entry)
        return entry

    def recall(self, tenant_id: str, classification: str | None = None) -> tuple[MemoryEntry, ...]:
        if not tenant_id:
            raise ValueError("tenant is required")
        return tuple(
            item for item in self._memory
            if item.tenant_id == tenant_id
            and (classification is None or item.classification == classification)
        )

    def build(self, tenant_id: str, items: list[ContextItem]) -> str:
        if not tenant_id:
            raise ValueError("tenant is required")
        selected: list[str] = []
        for item in items:
            if not item.trusted and not self.policy.allow_untrusted_content:
                continue
            content = self.redact_sensitive(item.content)
            selected.append(f"[{item.source}] {content}")
            if len(selected) >= self.policy.max_items:
                break
        return "\n".join(selected)[: self.policy.max_chars]

    def redact_sensitive(self, text: str) -> str:
        patterns = (
            r"(?i)(SECRET|API_KEY|PASSWORD|TOKEN|AUTHORIZATION)\\s*=\\s*[^\\s\\n]+",
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]*PRIVATE KEY-----",
            r"(?i)bearer\\s+[A-Za-z0-9._~+/=-]+",
        )
        result = text
        for pattern in patterns:
            result = re.sub(pattern, "[REDACTED]", result)
        return result
