import re
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Protocol
from uuid import UUID, uuid4

_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID = re.compile(r"^[0-9a-f]{16}$")


def _validate_trace_id(value: str | None) -> None:
    if value is not None and not _TRACE_ID.fullmatch(value):
        raise ValueError("trace_id must be a 32-character lowercase hexadecimal W3C trace id")


def _validate_span_id(value: str | None) -> None:
    if value is not None and not _SPAN_ID.fullmatch(value):
        raise ValueError("parent_span_id must be a 16-character lowercase hexadecimal span id")


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

    def __post_init__(self) -> None:
        if not self.tenant_id or self.tenant_id != self.tenant_id.strip() or not self.name.strip():
            raise ValueError("trace tenant and name are required")
        if self.started_at.tzinfo is None or self.started_at.utcoffset() is None:
            raise ValueError("trace start must be timezone-aware")
        if self.ended_at is not None and (
            self.ended_at.tzinfo is None or self.ended_at.utcoffset() is None
        ):
            raise ValueError("trace end must be timezone-aware")
        if self.ended_at is not None and self.ended_at < self.started_at:
            raise ValueError("trace end cannot precede start")
        _validate_trace_id(self.trace_id)
        _validate_span_id(self.parent_span_id)


@dataclass(frozen=True, slots=True)
class MetricPoint:
    tenant_id: str
    name: str
    value: float
    unit: str
    trace_id: str | None = None

    def __post_init__(self) -> None:
        if not self.tenant_id or self.tenant_id != self.tenant_id.strip():
            raise ValueError("metric tenant is required")
        if not self.name or self.name != self.name.strip() or not self.unit.strip():
            raise ValueError("metric identity is required")
        _validate_trace_id(self.trace_id)


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
        uuid4(),
        tenant_id,
        event_type,
        severity,
        datetime.now(UTC),
        actor_id,
        trace_id,
        run_id,
        execution_id,
        outcome,
        incident_id,
    )
