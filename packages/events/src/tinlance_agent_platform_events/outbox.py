from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid4

_MAX_EVENT_TYPE = 128
_MAX_PAYLOAD_FIELDS = 32
_MAX_PAYLOAD_VALUE = 4096


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
            or len(event.event_type) > _MAX_EVENT_TYPE
        ):
            raise ValueError("tenant and event type are required and bounded")
        if len(event.payload) > _MAX_PAYLOAD_FIELDS:
            raise ValueError("event payload has too many fields")
        if any(
            not key
            or not value
            or len(key) > 128
            or len(value) > _MAX_PAYLOAD_VALUE
            for key, value in event.payload.items()
        ):
            raise ValueError("event payload keys and values are required and bounded")
        secret_markers = ("secret", "password", "token", "private_key")
        if any(
            marker in f"{key}={value}".lower()
            for key, value in event.payload.items()
            for marker in secret_markers
        ):
            raise ValueError("secret-bearing event fields are forbidden")
        with self._lock:
            if event.event_id in self._ids:
                raise ValueError("event id already exists")
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
        if not tenant_id:
            raise ValueError("tenant is required")
        with self._lock:
            return tuple(
                event
                for event in self._events
                if event.tenant_id == tenant_id and event.run_id == run_id
            )


def new_event(
    tenant_id: str, run_id: UUID, event_type: str, payload: Mapping[str, str]
) -> Event:
    if not tenant_id or tenant_id != tenant_id.strip() or not event_type:
        raise ValueError("event identity is required")
    return Event(
        uuid4(),
        tenant_id,
        run_id,
        event_type,
        MappingProxyType(dict(payload)),
        datetime.now(UTC),
    )
