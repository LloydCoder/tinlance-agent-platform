"""Transactional outbox contracts and a deterministic reference implementation.

The Platform never treats publication to an external broker as part of the
security authority decision. Durable adapters must atomically persist the
business state and outbox record, then publish using the outbox lease.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class OutboxRecord:
    event_id: UUID
    tenant_id: str
    aggregate_id: UUID
    event_type: str
    payload: bytes
    created_at: datetime
    attempts: int = 0
    published_at: datetime | None = None
    lease_id: UUID | None = None


class TransactionalOutbox:
    """Thread-safe reference outbox; durable adapters must preserve its contract."""

    def __init__(self) -> None:
        self._items: dict[UUID, OutboxRecord] = {}
        self._lock = RLock()

    def append(self, tenant_id: str, aggregate_id: UUID, event_type: str, payload: bytes) -> UUID:
        if not tenant_id or tenant_id != tenant_id.strip():
            raise ValueError("tenant_id must be normalized and non-empty")
        if not event_type or event_type != event_type.strip():
            raise ValueError("event_type must be normalized and non-empty")
        event_id = uuid4()
        with self._lock:
            self._items[event_id] = OutboxRecord(
                event_id,
                tenant_id,
                aggregate_id,
                event_type,
                bytes(payload),
                datetime.now(UTC),
            )
        return event_id

    def lease(self, *, limit: int = 100) -> tuple[OutboxRecord, ...]:
        if limit < 1:
            raise ValueError("limit must be positive")
        with self._lock:
            selected: list[OutboxRecord] = []
            lease_id = uuid4()
            for record in self._items.values():
                if record.published_at is not None or record.lease_id is not None:
                    continue
                leased = OutboxRecord(
                    record.event_id, record.tenant_id, record.aggregate_id, record.event_type,
                    record.payload,
                    record.created_at,
                    record.attempts + 1,
                    record.published_at,
                    lease_id,
                )
                self._items[record.event_id] = leased
                selected.append(leased)
                if len(selected) == limit:
                    break
            return tuple(selected)

    def acknowledge(self, event_id: UUID, lease_id: UUID) -> None:
        with self._lock:
            record = self._items.get(event_id)
            if record is None or record.lease_id != lease_id or record.published_at is not None:
                raise PermissionError("outbox acknowledgement does not match an active lease")
            self._items[event_id] = OutboxRecord(
                record.event_id, record.tenant_id, record.aggregate_id, record.event_type,
                record.payload,
                record.created_at,
                record.attempts,
                datetime.now(UTC),
                None,
            )

    def release(self, lease_id: UUID) -> int:
        released = 0
        with self._lock:
            for event_id, record in tuple(self._items.items()):
                if record.lease_id == lease_id and record.published_at is None:
                    self._items[event_id] = OutboxRecord(
                        record.event_id, record.tenant_id, record.aggregate_id, record.event_type,
                        record.payload,
                        record.created_at,
                        record.attempts,
                        record.published_at,
                        None,
                    )
                    released += 1
        return released

    def pending(self) -> tuple[OutboxRecord, ...]:
        with self._lock:
            return tuple(r for r in self._items.values() if r.published_at is None)
