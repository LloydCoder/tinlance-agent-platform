from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class Event:
    event_id: UUID
    tenant_id: str
    run_id: UUID
    event_type: str
    payload: dict[str, str]
    occurred_at: datetime


class EventStore(Protocol):
    def append(self, event: Event) -> Event: ...

    def list_for_run(self, tenant_id: str, run_id: UUID) -> tuple[Event, ...]: ...


class InMemoryEventStore:
    def __init__(self) -> None:
        self._events: list[Event] = []

    def append(self, event: Event) -> Event:
        if not event.tenant_id:
            raise ValueError("tenant is required")
        self._events.append(event)
        return event

    def list_for_run(self, tenant_id: str, run_id: UUID) -> tuple[Event, ...]:
        return tuple(
            event
            for event in self._events
            if event.tenant_id == tenant_id and event.run_id == run_id
        )


def new_event(tenant_id: str, run_id: UUID, event_type: str, payload: dict[str, str]) -> Event:
    return Event(uuid4(), tenant_id, run_id, event_type, dict(payload), datetime.now(UTC))
