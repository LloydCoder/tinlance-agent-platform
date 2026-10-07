from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from threading import RLock
from typing import Protocol
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class AuditRecord:
    audit_id: UUID
    tenant_id: str
    run_id: UUID
    actor_id: str
    action: str
    resource: str
    decision: str
    occurred_at: datetime
    previous_hash: str
    record_hash: str
    sequence: int = 0
    execution_id: UUID | None = None
    intent_fingerprint: str | None = None


class AuditStore(Protocol):
    def append(
        self,
        tenant_id: str,
        run_id: UUID,
        actor_id: str,
        action: str,
        resource: str,
        decision: str,
        occurred_at: datetime | None = None,
        execution_id: UUID | None = None,
        intent_fingerprint: str | None = None,
    ) -> AuditRecord: ...

    def list_for_run(self, tenant_id: str, run_id: UUID) -> tuple[AuditRecord, ...]: ...

    def verify(self, tenant_id: str, run_id: UUID) -> bool: ...


class InMemoryAuditStore:
    def __init__(self) -> None:
        self._records: list[AuditRecord] = []
        self._lock = RLock()

    @staticmethod
    def _hash(record: AuditRecord) -> str:
        canonical = "|".join(
            (
                str(record.audit_id),
                record.tenant_id,
                str(record.run_id),
                record.actor_id,
                record.action,
                record.resource,
                record.decision,
                record.occurred_at.isoformat(),
                record.previous_hash,
                str(record.sequence),
                str(record.execution_id or ""),
                record.intent_fingerprint or "",
            )
        )
        return sha256(canonical.encode()).hexdigest()

    def append(
        self,
        tenant_id: str,
        run_id: UUID,
        actor_id: str,
        action: str,
        resource: str,
        decision: str,
        occurred_at: datetime | None = None,
        execution_id: UUID | None = None,
        intent_fingerprint: str | None = None,
    ) -> AuditRecord:
        values = (tenant_id, actor_id, action, resource, decision)
        if any(not value or value != value.strip() for value in values):
            raise ValueError("audit identity fields must be normalized")
        if any(len(value) > 4096 for value in values):
            raise ValueError("audit identity fields exceed safety limits")
        if intent_fingerprint is not None and not intent_fingerprint.strip():
            raise ValueError("intent fingerprint must be normalized")
        observed = occurred_at or datetime.now(UTC)
        if observed.tzinfo is None or observed.utcoffset() is None:
            raise ValueError("audit timestamp must be timezone-aware")
        with self._lock:
            previous_record = next(
                (
                    record
                    for record in reversed(self._records)
                    if record.tenant_id == tenant_id and record.run_id == run_id
                ),
                None,
            )
            previous = previous_record.record_hash if previous_record else ""
            sequence = previous_record.sequence + 1 if previous_record else 1
            record = AuditRecord(
                uuid4(),
                tenant_id,
                run_id,
                actor_id,
                action,
                resource,
                decision,
                observed,
                previous,
                "",
                sequence,
                execution_id,
                intent_fingerprint,
            )
            record = AuditRecord(
                record.audit_id,
                record.tenant_id,
                record.run_id,
                record.actor_id,
                record.action,
                record.resource,
                record.decision,
                record.occurred_at,
                record.previous_hash,
                self._hash(record),
                record.sequence,
                record.execution_id,
                record.intent_fingerprint,
            )
            self._records.append(record)
            return record

    def list_for_run(self, tenant_id: str, run_id: UUID) -> tuple[AuditRecord, ...]:
        with self._lock:
            return tuple(
                record
                for record in self._records
                if record.tenant_id == tenant_id and record.run_id == run_id
            )

    def verify(self, tenant_id: str, run_id: UUID) -> bool:
        previous = ""
        expected_sequence = 1
        for record in self.list_for_run(tenant_id, run_id):
            if (
                record.sequence != expected_sequence
                or record.previous_hash != previous
                or record.record_hash != self._hash(record)
            ):
                return False
            previous = record.record_hash
            expected_sequence += 1
        return True
