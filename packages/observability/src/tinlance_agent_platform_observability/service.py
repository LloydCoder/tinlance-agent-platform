from dataclasses import dataclass
from datetime import UTC,datetime
from typing import Protocol
from uuid import UUID,uuid4
@dataclass(frozen=True,slots=True)
class TraceSpan:
    span_id:UUID; tenant_id:str; run_id:UUID; name:str; started_at:datetime; ended_at:datetime|None=None; attributes:tuple[tuple[str,str],...]=()
@dataclass(frozen=True,slots=True)
class MetricPoint:
    tenant_id:str; name:str; value:float; unit:str
@dataclass(frozen=True,slots=True)
class SecurityEvent:
    event_id:UUID; tenant_id:str; event_type:str; severity:str; occurred_at:datetime; run_id:UUID|None=None
class ObservabilitySink(Protocol):
    def emit_span(self,span:TraceSpan)->None: ...
    def emit_metric(self,metric:MetricPoint)->None: ...
    def emit_security(self,event:SecurityEvent)->None: ...
class InMemoryObservabilitySink:
    def __init__(self)->None: self.spans:list[TraceSpan]=[]; self.metrics:list[MetricPoint]=[]; self.security:list[SecurityEvent]=[]
    def emit_span(self,span:TraceSpan)->None: self.spans.append(span)
    def emit_metric(self,metric:MetricPoint)->None: self.metrics.append(metric)
    def emit_security(self,event:SecurityEvent)->None: self.security.append(event)
def new_security_event(tenant_id:str,event_type:str,severity:str,run_id:UUID|None=None)->SecurityEvent:
    if not tenant_id or severity not in {"info","warning","critical"}: raise ValueError("invalid security event")
    return SecurityEvent(uuid4(),tenant_id,event_type,severity,datetime.now(UTC),run_id)
