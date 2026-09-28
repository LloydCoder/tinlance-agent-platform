from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class Evidence:
    evidence_id: UUID
    tenant_id: str
    run_id: UUID
    content_hash: str
    content: str
    sequence: int


class EvidenceStore(Protocol):
    def append(self, tenant_id: str, run_id: UUID, content: str) -> Evidence: ...


class InMemoryEvidenceStore:
    def __init__(self) -> None:
        self._items: list[Evidence] = []

    def append(self, tenant_id: str, run_id: UUID, content: str) -> Evidence:
        if not tenant_id or not content:
            raise ValueError("tenant and content are required")
        sequence = 1 + max(
            (
                evidence.sequence
                for evidence in self._items
                if evidence.tenant_id == tenant_id and evidence.run_id == run_id
            ),
            default=0,
        )
        digest = sha256(content.encode("utf-8")).hexdigest()
        item = Evidence(uuid4(), tenant_id, run_id, digest, content, sequence)
        self._items.append(item)
        return item
