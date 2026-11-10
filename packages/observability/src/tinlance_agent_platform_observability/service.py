import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Protocol
from uuid import UUID, uuid4

_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID = re.compile(r"^[0-9a-f]{16}$")


def validate_trace_id(value: str | None) -> None:
    if value is not None and (not _TRACE_ID.fullmatch(value) or value == "0" * 32):
        raise ValueError(
            "trace_id must be a non-zero 32-character lowercase hexadecimal W3C trace id"
        )


def validate_span_id(value: str | None) -> None:
    if value is not None and (not _SPAN_ID.fullmatch(value) or value == "0" * 16):
        raise ValueError(
            "parent_span_id must be a non-zero 16-character lowercase hexadecimal W3C span id"
        )


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
        validate_trace_id(self.trace_id)
        validate_span_id(self.parent_span_id)


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
        validate_trace_id(self.trace_id)


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

    def __post_init__(self) -> None:
        if (
            not self.tenant_id
            or self.tenant_id != self.tenant_id.strip()
            or not self.event_type
            or self.event_type != self.event_type.strip()
            or self.severity not in {"info", "warning", "critical"}
            or self.outcome not in {"allow", "deny", "unknown", "error"}
        ):
            raise ValueError("invalid security event")
        if self.actor_id is not None and (
            not self.actor_id or self.actor_id != self.actor_id.strip()
        ):
            raise ValueError("security event actor must be normalized")
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("security event timestamp must be timezone-aware")
        validate_trace_id(self.trace_id)


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



class OpenTelemetrySpan(Protocol):
    def set_attribute(self, key: str, value: object) -> None: ...
    def end(self, *, end_time: int | None = None) -> None: ...


class OpenTelemetryTracer(Protocol):
    def start_span(self, name: str, **kwargs: object) -> OpenTelemetrySpan: ...


class OpenTelemetryHistogram(Protocol):
    def record(self, amount: float, attributes: dict[str, object] | None = None) -> None: ...


class OpenTelemetryMeter(Protocol):
    def create_histogram(
        self, name: str, *, unit: str = "", description: str = ""
    ) -> OpenTelemetryHistogram: ...


class OpenTelemetryLogger(Protocol):
    def emit(
        self,
        *,
        body: str,
        attributes: dict[str, object],
        severity_text: str,
        timestamp: int,
        event_name: str,
    ) -> None: ...


class OpenTelemetryObservabilitySink:
    """Production sink over injected OpenTelemetry API tracer, meter and logger objects.

    The application owns SDK/exporter configuration. Existing W3C trace IDs require a
    context_factory that builds an OpenTelemetry Context with the supplied trace/parent IDs.
    Only completed spans are exported; metrics intentionally omit tenant IDs to avoid
    unbounded high-cardinality dimensions.
    """

    def __init__(
        self,
        *,
        tracer: OpenTelemetryTracer,
        meter: OpenTelemetryMeter,
        logger: OpenTelemetryLogger,
        context_factory: Callable[[str, str | None], object] | None = None,
    ) -> None:
        self._tracer = tracer
        self._meter = meter
        self._logger = logger
        self._context_factory = context_factory
        self._histograms: dict[tuple[str, str], OpenTelemetryHistogram] = {}
        self._lock = RLock()

    @staticmethod
    def _epoch_ns(value: datetime) -> int:
        return int(value.timestamp() * 1_000_000_000)

    def emit_span(self, span: TraceSpan) -> None:
        if span.ended_at is None:
            raise ValueError("OpenTelemetry sink exports completed spans only")
        if span.parent_span_id is not None and span.trace_id is None:
            raise ValueError("W3C parent span requires a trace ID")
        kwargs: dict[str, object] = {"start_time": self._epoch_ns(span.started_at)}
        if span.trace_id is not None:
            if self._context_factory is None:
                raise ValueError("OpenTelemetry context factory is required for W3C trace IDs")
            kwargs["context"] = self._context_factory(span.trace_id, span.parent_span_id)
        otel_span = self._tracer.start_span(span.name, **kwargs)
        attributes: dict[str, object] = {
            "platform.tenant_id": span.tenant_id,
            "platform.run_id": str(span.run_id),
            "platform.span_id": str(span.span_id),
            "platform.status": span.status,
        }
        if span.trace_id is not None:
            attributes["w3c.trace_id"] = span.trace_id
        if span.parent_span_id is not None:
            attributes["w3c.parent_span_id"] = span.parent_span_id
        for key, value in attributes.items():
            otel_span.set_attribute(key, value)
        otel_span.end(end_time=self._epoch_ns(span.ended_at))

    def emit_metric(self, metric: MetricPoint) -> None:
        key = (metric.name, metric.unit)
        with self._lock:
            histogram = self._histograms.get(key)
            if histogram is None:
                histogram = self._meter.create_histogram(
                    metric.name,
                    unit=metric.unit,
                    description="Tinlance Agent Platform metric observations",
                )
                self._histograms[key] = histogram
        histogram.record(float(metric.value))

    def emit_security(self, event: SecurityEvent) -> None:
        attributes: dict[str, object] = {
            "platform.event_id": str(event.event_id),
            "platform.tenant_id": event.tenant_id,
            "platform.event_type": event.event_type,
            "platform.severity": event.severity,
            "platform.outcome": event.outcome,
        }
        optional_attributes = {
            "platform.actor_id": event.actor_id,
            "w3c.trace_id": event.trace_id,
            "platform.run_id": str(event.run_id) if event.run_id is not None else None,
            "platform.execution_id": (
                str(event.execution_id) if event.execution_id is not None else None
            ),
            "platform.incident_id": (
                str(event.incident_id) if event.incident_id is not None else None
            ),
        }
        attributes.update(
            {key: value for key, value in optional_attributes.items() if value is not None}
        )
        self._logger.emit(
            body=event.event_type,
            attributes=attributes,
            severity_text=event.severity.upper(),
            timestamp=self._epoch_ns(event.occurred_at),
            event_name=event.event_type,
        )


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
