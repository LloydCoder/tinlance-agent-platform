from dataclasses import dataclass
from datetime import UTC,datetime
from typing import Protocol
from uuid import UUID,uuid4
@dataclass(frozen=True,slots=True)
class Event:
    event_id:UUID; tenant_id:str; run_id:UUID; event_type:str; payload:dict[str,str]; occurred_at:datetime; idempotency_key:str|None=None
class EventStore(Protocol):
    def append(self,event:Event)->Event: ...
    def append_once(self,event:Event)->Event: ...
    def list_for_run(self,tenant_id:str,run_id:UUID)->tuple[Event,...]: ...
class InMemoryEventStore:
    def __init__(self)->None: self._events:list[Event]=[]; self._keys:dict[tuple[str,str],UUID]={}
    def append(self,event:Event)->Event:
        if not event.tenant_id or not event.event_type: raise ValueError("tenant and event type are required")
        self._events.append(event); return event
    def append_once(self,event:Event)->Event:
        if event.idempotency_key:
            key=(event.tenant_id,event.idempotency_key); existing=self._keys.get(key)
            if existing is not None: return next(e for e in self._events if e.event_id==existing)
            self._keys[key]=event.event_id
        return self.append(event)
    def list_for_run(self,tenant_id:str,run_id:UUID)->tuple[Event,...]: return tuple(e for e in self._events if e.tenant_id==tenant_id and e.run_id==run_id)
def new_event(tenant_id:str,run_id:UUID,event_type:str,payload:dict[str,str],idempotency_key:str|None=None)->Event:
    return Event(uuid4(),tenant_id,run_id,event_type,dict(payload),datetime.now(UTC),idempotency_key)
