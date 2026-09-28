from dataclasses import dataclass
from hashlib import sha256
from threading import RLock
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
    def append(
        self, tenant_id: str, run_id: UUID, event_type: str, payload: str
    ) -> TrajectoryEvent: ...

    def verify(self, tenant_id: str, run_id: UUID) -> bool: ...


class InMemoryTrajectoryStore:
    def __init__(self) -> None:
        self._events: list[TrajectoryEvent] = []
        self._lock = RLock()

    def append(
        self, tenant_id: str, run_id: UUID, event_type: str, payload: str
    ) -> TrajectoryEvent:
        if not tenant_id or tenant_id != tenant_id.strip() or not event_type or not payload:
            raise ValueError("trajectory event fields are required")
        with self._lock:
            run_events = [
                event
                for event in self._events
                if event.tenant_id == tenant_id and event.run_id == run_id
            ]
            previous = run_events[-1].event_hash if run_events else "GENESIS"
            sequence = len(run_events) + 1
            event_id = uuid4()
            material = (
                f"{tenant_id}|{run_id}|{sequence}|{event_type}|{payload}|{previous}"
            ).encode()
            event_hash = sha256(material).hexdigest()
            event = TrajectoryEvent(
                event_id,
                tenant_id,
                run_id,
                sequence,
                event_type,
                payload,
                previous,
                event_hash,
            )
            self._events.append(event)
            return event

    def verify(self, tenant_id: str, run_id: UUID) -> bool:
        with self._lock:
            events = [
                event
                for event in self._events
                if event.tenant_id == tenant_id and event.run_id == run_id
            ]
            previous = "GENESIS"
            for expected_sequence, event in enumerate(events, start=1):
                material = (
                    f"{tenant_id}|{run_id}|{event.sequence}|{event.event_type}|"
                    f"{event.payload}|{previous}"
                ).encode()
                if (
                    event.sequence != expected_sequence
                    or event.previous_hash != previous
                    or event.event_hash != sha256(material).hexdigest()
                ):
                    return False
                previous = event.event_hash
            return True
