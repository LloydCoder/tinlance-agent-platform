from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class TrajectoryEvent:
    event_id: UUID
    tenant_id: str
    run_id: UUID
    sequence: int
    event_type: str
    payload: str
    previous_hash: str
    event_hash: str


class TrajectoryStore(Protocol):
    def append(self, tenant_id: str, run_id: UUID, event_type: str, payload: str) -> TrajectoryEvent: ...


class InMemoryTrajectoryStore:
    def __init__(self) -> None:
        self._events: list[TrajectoryEvent] = []

    def append(self, tenant_id: str, run_id: UUID, event_type: str, payload: str) -> TrajectoryEvent:
        previous = next((e.event_hash for e in reversed(self._events) if e.tenant_id == tenant_id and e.run_id == run_id), "GENESIS")
        sequence = 1 + max((e.sequence for e in self._events if e.tenant_id == tenant_id and e.run_id == run_id), default=0)
        event_id = uuid4()
        material = f"{tenant_id}|{run_id}|{sequence}|{event_type}|{payload}|{previous}".encode()
        event_hash = sha256(material).hexdigest()
        event = TrajectoryEvent(event_id, tenant_id, run_id, sequence, event_type, payload, previous, event_hash)
        self._events.append(event)
        return event

    def verify(self, tenant_id: str, run_id: UUID) -> bool:
        events = [e for e in self._events if e.tenant_id == tenant_id and e.run_id == run_id]
        previous = "GENESIS"
        for event in events:
            material = f"{tenant_id}|{run_id}|{event.sequence}|{event.event_type}|{event.payload}|{previous}".encode()
            if event.previous_hash != previous or event.event_hash != sha256(material).hexdigest():
                return False
            previous = event.event_hash
        return True
