from dataclasses import dataclass
from datetime import UTC, datetime
from collections.abc import Mapping
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

    def append(self, event: Event) -> Event:
        if not event.tenant_id or not event.event_type:
            raise ValueError("tenant and event type are required")
        if event.event_id in self._ids:
            raise ValueError("event id already exists")
        if any("secret" in key.lower() for key in event.payload):
            raise ValueError("secret-bearing event fields are forbidden")
        stored = Event(
            event.event_id,
            event.tenant_id,
            event.run_id,
            event.event_type,
            MappingProxyType(dict(event.payload)),
            event.occurred_at,
        )
        self._events.append(stored)
        self._ids.add(event.event_id)
        return stored

    def list_for_run(self, tenant_id: str, run_id: UUID) -> tuple[Event, ...]:
        return tuple(
            event
            for event in self._events
            if event.tenant_id == tenant_id and event.run_id == run_id
        )


def new_event(
    tenant_id: str, run_id: UUID, event_type: str, payload: Mapping[str, str]
) -> Event:
    return Event(
        uuid4(), tenant_id, run_id, event_type, MappingProxyType(dict(payload)), datetime.now(UTC)
    )
