from dataclasses import dataclass
from datetime import UTC, datetime
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
    outcome: str = "unknown"


class ObservabilitySink(Protocol):
    def emit_span(self, span: TraceSpan) -> None: ...
    def emit_metric(self, metric: MetricPoint) -> None: ...
    def emit_security(self, event: SecurityEvent) -> None: ...


class InMemoryObservabilitySink:
    def __init__(self, max_items: int = 10_000) -> None:
        if max_items < 1:
            raise ValueError("max_items must be positive")
        self.max_items = max_items
        self._spans: list[TraceSpan] = []
        self._metrics: list[MetricPoint] = []
        self._security: list[SecurityEvent] = []

    def emit_span(self, span: TraceSpan) -> None:
        if len(self._spans) >= self.max_items:
            raise RuntimeError("observability span buffer is full")
        self._spans.append(span)

    def emit_metric(self, metric: MetricPoint) -> None:
        if len(self._metrics) >= self.max_items:
            raise RuntimeError("observability metric buffer is full")
        self._metrics.append(metric)

    def emit_security(self, event: SecurityEvent) -> None:
        if len(self._security) >= self.max_items:
            raise RuntimeError("observability security buffer is full")
        self._security.append(event)

    @property
    def spans(self) -> tuple[TraceSpan, ...]:
        return tuple(self._spans)

    @property
    def metrics(self) -> tuple[MetricPoint, ...]:
        return tuple(self._metrics)

    @property
    def security(self) -> tuple[SecurityEvent, ...]:
        return tuple(self._security)


def new_security_event(
    tenant_id: str,
    event_type: str,
    severity: str,
    *,
    actor_id: str | None = None,
    trace_id: str | None = None,
    outcome: str = "unknown",
) -> SecurityEvent:
    if (
        not tenant_id
        or tenant_id != tenant_id.strip()
        or not event_type
        or severity not in {"info", "warning", "critical"}
    ):
        raise ValueError("invalid security event")
    return SecurityEvent(
        uuid4(), tenant_id, event_type, severity, datetime.now(UTC), actor_id, trace_id, outcome
    )
