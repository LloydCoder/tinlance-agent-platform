"""Distributed worker lease contract with a reference implementation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import RLock
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class WorkLease:
    lease_id: UUID
    work_id: UUID
    owner: str
    expires_at: datetime


class WorkLeaseStore:
    """Reference semantics for single-owner work claiming and renewal."""

    def __init__(self) -> None:
        self._items: dict[UUID, WorkLease] = {}
        self._lock = RLock()

    def claim(self, work_id: UUID, owner: str, *, ttl_seconds: float = 30.0) -> WorkLease | None:
        if not owner or owner != owner.strip() or ttl_seconds <= 0:
            raise ValueError("owner and positive lease TTL are required")
        now = datetime.now(UTC)
        with self._lock:
            current = self._items.get(work_id)
            if current is not None and current.expires_at > now:
                return None
            lease = WorkLease(uuid4(), work_id, owner, now + timedelta(seconds=ttl_seconds))
            self._items[work_id] = lease
            return lease

    def renew(self, lease: WorkLease, *, ttl_seconds: float = 30.0) -> WorkLease:
        if ttl_seconds <= 0:
            raise ValueError("lease TTL must be positive")
        now = datetime.now(UTC)
        with self._lock:
            current = self._items.get(lease.work_id)
            if current != lease or current.expires_at <= now:
                raise PermissionError("lease is not active")
            renewed = WorkLease(
                lease.lease_id,
                lease.work_id,
                lease.owner,
                now + timedelta(seconds=ttl_seconds),
            )
            self._items[lease.work_id] = renewed
            return renewed

    def release(self, lease: WorkLease) -> None:
        with self._lock:
            if self._items.get(lease.work_id) == lease:
                del self._items[lease.work_id]
