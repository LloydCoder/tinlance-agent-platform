from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Protocol
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class TraceSpan:
    span_id: UUID
    tenant_id: str
    run_id: UUID
    name: str
    started_at: datetime
    ended_at: datetime | None = None
    trace_id: str | None = None
    parent_span_id: str | None = None
    status: str = "unset"


@dataclass(frozen=True, slots=True)
class MetricPoint:
    tenant_id: str
    name: str
    value: float
    unit: str
    trace_id: str | None = None


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    event_id: UUID
    tenant_id: str
    event_type: str
    severity: str
    occurred_at: datetime
    actor_id: str | None = None
    trace_id: str | None = None
    run_id: UUID | None = None
    execution_id: UUID | None = None
    outcome: str = "unknown"
    incident_id: UUID | None = None


class ObservabilitySink(Protocol):
    def emit_span(self, span: TraceSpan) -> None: ...
    def emit_metric(self, metric: MetricPoint) -> None: ...
    def emit_security(self, event: SecurityEvent) -> None: ...


class InMemoryObservabilitySink:
    def __init__(self) -> None:
        self._spans: list[TraceSpan] = []
        self._metrics: list[MetricPoint] = []
        self._security: list[SecurityEvent] = []
        self._lock = RLock()

    @property
    def spans(self) -> tuple[TraceSpan, ...]:
        with self._lock:
            return tuple(self._spans)

    @property
    def metrics(self) -> tuple[MetricPoint, ...]:
        with self._lock:
            return tuple(self._metrics)

    @property
    def security(self) -> tuple[SecurityEvent, ...]:
        with self._lock:
            return tuple(self._security)

    def emit_span(self, span: TraceSpan) -> None:
        with self._lock:
            self._spans.append(span)

    def emit_metric(self, metric: MetricPoint) -> None:
        with self._lock:
            self._metrics.append(metric)

    def emit_security(self, event: SecurityEvent) -> None:
        with self._lock:
            self._security.append(event)


def new_security_event(
    tenant_id: str,
    event_type: str,
    severity: str,
    *,
    actor_id: str | None = None,
    trace_id: str | None = None,
    run_id: UUID | None = None,
    execution_id: UUID | None = None,
    outcome: str = "unknown",
    incident_id: UUID | None = None,
) -> SecurityEvent:
    if (
        not tenant_id
        or tenant_id != tenant_id.strip()
        or not event_type
        or event_type != event_type.strip()
        or severity not in {"info", "warning", "critical"}
        or outcome not in {"allow", "deny", "unknown", "error"}
    ):
        raise ValueError("invalid security event")
    return SecurityEvent(
        uuid4(), tenant_id, event_type, severity, datetime.now(UTC), actor_id, trace_id,
        run_id, execution_id, outcome, incident_id,
    )
