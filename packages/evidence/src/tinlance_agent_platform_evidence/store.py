from dataclasses import dataclass
from datetime import UTC, datetime
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
    execution_id: UUID | None = None
    actor_id: str | None = None
    provenance: str = "platform"
    occurred_at: datetime = datetime.min.replace(tzinfo=UTC)
    previous_hash: str = ""
    record_hash: str = ""


class EvidenceStore(Protocol):
    def append(
        self,
        tenant_id: str,
        run_id: UUID,
        content: str,
        execution_id: UUID | None = None,
        *,
        actor_id: str | None = None,
        provenance: str = "platform",
        occurred_at: datetime | None = None,
    ) -> Evidence: ...

    def list_for_run(self, tenant_id: str, run_id: UUID) -> tuple[Evidence, ...]: ...

    def verify(self, tenant_id: str, run_id: UUID) -> bool: ...


class InMemoryEvidenceStore:
    def __init__(self) -> None:
        self._items: list[Evidence] = []
        self._lock = RLock()

    @staticmethod
    def _record_hash(item: Evidence) -> str:
        canonical = "|".join(
            (
                item.tenant_id,
                str(item.run_id),
                str(item.sequence),
                item.content_hash,
                str(item.execution_id or ""),
                str(item.actor_id or ""),
                item.provenance,
                item.occurred_at.isoformat(),
                item.previous_hash,
            )
        )
        return sha256(canonical.encode()).hexdigest()

    def append(
        self,
        tenant_id: str,
        run_id: UUID,
        content: str,
        execution_id: UUID | None = None,
        *,
        actor_id: str | None = None,
        provenance: str = "platform",
        occurred_at: datetime | None = None,
    ) -> Evidence:
        if (
            not tenant_id
            or tenant_id != tenant_id.strip()
            or not content
            or len(content) > _MAX_CONTENT
        ):
            raise ValueError("tenant and bounded content are required")
        if actor_id is not None and (not actor_id or actor_id != actor_id.strip()):
            raise ValueError("actor identifier must be normalized")
        if not provenance or provenance != provenance.strip():
            raise ValueError("evidence provenance is required")
        observed = occurred_at or datetime.now(UTC)
        if observed.tzinfo is None or observed.utcoffset() is None:
            raise ValueError("evidence timestamp must be timezone-aware")
        with self._lock:
            sequence = 1 + max(
                (
                    evidence.sequence
                    for evidence in self._items
                    if evidence.tenant_id == tenant_id and evidence.run_id == run_id
                ),
                default=0,
            )
            previous = next(
                (
                    evidence.record_hash
                    for evidence in reversed(self._items)
                    if evidence.tenant_id == tenant_id and evidence.run_id == run_id
                ),
                "",
            )
            digest = sha256(content.encode()).hexdigest()
            item = Evidence(
                uuid4(),
                tenant_id,
                run_id,
                digest,
                content,
                sequence,
                execution_id,
                actor_id,
                provenance,
                observed,
                previous,
            )
            item = Evidence(
                item.evidence_id,
                item.tenant_id,
                item.run_id,
                item.content_hash,
                item.content,
                item.sequence,
                item.execution_id,
                item.actor_id,
                item.provenance,
                item.occurred_at,
                item.previous_hash,
                self._record_hash(item),
            )
            self._items.append(item)
            return item

    def list_for_run(self, tenant_id: str, run_id: UUID) -> tuple[Evidence, ...]:
        if not tenant_id or tenant_id != tenant_id.strip():
            raise ValueError("tenant identifier must be normalized")
        with self._lock:
            return tuple(
                item
                for item in self._items
                if item.tenant_id == tenant_id and item.run_id == run_id
            )

    def verify(self, tenant_id: str, run_id: UUID) -> bool:
        items = self.list_for_run(tenant_id, run_id)
        previous = ""
        for index, item in enumerate(items, start=1):
            if item.sequence != index:
                return False
            if item.content_hash != sha256(item.content.encode()).hexdigest():
                return False
            if item.previous_hash != previous:
                return False
            if item.record_hash != self._record_hash(item):
                return False
            previous = item.record_hash
        return True
