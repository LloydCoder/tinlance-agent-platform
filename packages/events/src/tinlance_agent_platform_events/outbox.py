from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class Event:
    event_id: UUID
    tenant_id: str
    run_id: UUID
    event_type: str
    payload: Mapping[str, str]
    occurred_at: datetime


class EventStore(Protocol):
    def append(self, event: Event) -> Event: ...
    def list_for_run(self, tenant_id: str, run_id: UUID) -> tuple[Event, ...]: ...


class InMemoryEventStore:
    def __init__(self) -> None:
        self._events: list[Event] = []
        self._ids: set[UUID] = set()
        self._lock = RLock()

    def append(self, event: Event) -> Event:
        if (
            not event.tenant_id
            or event.tenant_id != event.tenant_id.strip()
            or not event.event_type
            or event.event_type != event.event_type.strip()
            or event.occurred_at.tzinfo is None
            or event.occurred_at.utcoffset() is None
        ):
            raise ValueError("invalid event identity or timestamp")
        if event.event_id in self._ids:
            raise ValueError("event id already exists")
        if len(event.payload) > 64:
            raise ValueError("event payload has too many fields")
        sensitive_markers = ("secret", "password", "token", "api_key", "private_key", "credential")
        if any(
            any(marker in key.lower() or marker in value.lower() for marker in sensitive_markers)
            for key, value in event.payload.items()
        ):
            raise ValueError("sensitive event fields are forbidden")
        stored = Event(
            event.event_id,
            event.tenant_id,
            event.run_id,
            event.event_type,
            MappingProxyType(dict(event.payload)),
            event.occurred_at,
        )
        with self._lock:
            if event.event_id in self._ids:
                raise ValueError("event id already exists")
            self._events.append(stored)
            self._ids.add(event.event_id)
        return stored

    def list_for_run(self, tenant_id: str, run_id: UUID) -> tuple[Event, ...]:
        if not tenant_id or tenant_id != tenant_id.strip():
            raise ValueError("tenant identifier must be normalized")
        with self._lock:
            return tuple(
                event
                for event in self._events
                if event.tenant_id == tenant_id and event.run_id == run_id
            )


def new_event(tenant_id: str, run_id: UUID, event_type: str, payload: Mapping[str, str]) -> Event:
    if not tenant_id or tenant_id != tenant_id.strip():
        raise ValueError("tenant identifier must be normalized")
    if not event_type or event_type != event_type.strip():
        raise ValueError("event type must be normalized")
    return Event(
        uuid4(), tenant_id, run_id, event_type, MappingProxyType(dict(payload)), datetime.now(UTC)
    )
