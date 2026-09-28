from dataclasses import dataclass
from hashlib import sha256
from threading import RLock
from typing import Protocol
from uuid import UUID, uuid4

_MAX_CONTENT = 1_000_000


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

    def list_for_run(self, tenant_id: str, run_id: UUID) -> tuple[Evidence, ...]: ...

    def verify(self, tenant_id: str, run_id: UUID) -> bool: ...


class InMemoryEvidenceStore:
    def __init__(self) -> None:
        self._items: list[Evidence] = []
        self._lock = RLock()

    def append(self, tenant_id: str, run_id: UUID, content: str) -> Evidence:
        if (
            not tenant_id
            or tenant_id != tenant_id.strip()
            or not content
            or len(content) > _MAX_CONTENT
        ):
            raise ValueError("tenant and bounded content are required")
        with self._lock:
            sequence = 1 + max(
                (
                    evidence.sequence
                    for evidence in self._items
                    if evidence.tenant_id == tenant_id and evidence.run_id == run_id
                ),
                default=0,
            )
            digest = sha256(content.encode()).hexdigest()
            item = Evidence(uuid4(), tenant_id, run_id, digest, content, sequence)
            self._items.append(item)
            return item

    def list_for_run(self, tenant_id: str, run_id: UUID) -> tuple[Evidence, ...]:
        with self._lock:
            return tuple(
                item
                for item in self._items
                if item.tenant_id == tenant_id and item.run_id == run_id
            )

    def verify(self, tenant_id: str, run_id: UUID) -> bool:
        with self._lock:
            items = self.list_for_run(tenant_id, run_id)
            return all(
                item.sequence == index
                and item.content_hash == sha256(item.content.encode()).hexdigest()
                for index, item in enumerate(items, start=1)
            )
