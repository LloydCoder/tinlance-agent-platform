from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from tinlance_agent_platform_observability.service import (
    MetricPoint,
    OpenTelemetryObservabilitySink,
    SecurityEvent,
    TraceSpan,
)


class FakeSpan:
    def __init__(self) -> None:
        self.attributes: dict[str, object] = {}
        self.start_time: int | None = None
        self.end_time: int | None = None

    def set_attribute(self, key: str, value: object) -> None:
        self.attributes[key] = value

    def end(self, *, end_time: int | None = None) -> None:
        self.end_time = end_time


class FakeTracer:
    def __init__(self) -> None:
        self.spans: list[FakeSpan] = []
        self.calls: list[dict[str, object]] = []

    def start_span(self, name: str, **kwargs: object) -> FakeSpan:
        span = FakeSpan()
        self.spans.append(span)
        self.calls.append({"name": name, **kwargs})
        return span


class FakeHistogram:
    def __init__(self) -> None:
        self.records: list[tuple[float, dict[str, object] | None]] = []

    def record(
        self, amount: float, attributes: dict[str, object] | None = None
    ) -> None:
        self.records.append((amount, attributes))


class FakeMeter:
    def __init__(self) -> None:
        self.histograms: dict[tuple[str, str], FakeHistogram] = {}

    def create_histogram(
        self, name: str, *, unit: str = "", description: str = ""
    ) -> FakeHistogram:
        histogram = FakeHistogram()
        self.histograms[(name, unit)] = histogram
        return histogram


class FakeLogger:
    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    def emit(self, **kwargs: object) -> None:
        self.records.append(kwargs)


def test_otel_sink_exports_completed_span_with_w3c_parent_context() -> None:
    tracer, meter, logger = FakeTracer(), FakeMeter(), FakeLogger()
    parent_context = object()
    sink = OpenTelemetryObservabilitySink(
        tracer=tracer,
        meter=meter,
        logger=logger,
        context_factory=lambda trace_id, parent_span_id: parent_context,
    )
    started = datetime(2026, 11, 10, 8, 0, tzinfo=UTC)
    ended = datetime(2026, 11, 10, 8, 0, 1, tzinfo=UTC)
    span = TraceSpan(
        uuid4(),
        "tenant-a",
        uuid4(),
        "agent.execute",
        started,
        ended,
        trace_id="0123456789abcdef0123456789abcdef",
        parent_span_id="0123456789abcdef",
    )

    sink.emit_span(span)

    assert tracer.calls[0]["context"] is parent_context
    assert tracer.calls[0]["start_time"] == int(started.timestamp() * 1_000_000_000)
    assert tracer.spans[0].end_time == int(ended.timestamp() * 1_000_000_000)
    assert tracer.spans[0].attributes["platform.tenant_id"] == "tenant-a"
    assert tracer.spans[0].attributes["platform.run_id"] == str(span.run_id)


def test_otel_sink_requires_context_factory_for_existing_trace_ids() -> None:
    sink = OpenTelemetryObservabilitySink(
        tracer=FakeTracer(),
        meter=FakeMeter(),
        logger=FakeLogger(),
    )
    span = TraceSpan(
        uuid4(),
        "tenant-a",
        uuid4(),
        "agent.execute",
        datetime.now(UTC),
        datetime.now(UTC),
        trace_id="0123456789abcdef0123456789abcdef",
    )

    with pytest.raises(ValueError, match="context factory"):
        sink.emit_span(span)


def test_otel_sink_rejects_incomplete_spans_instead_of_leaking_open_spans() -> None:
    sink = OpenTelemetryObservabilitySink(
        tracer=FakeTracer(),
        meter=FakeMeter(),
        logger=FakeLogger(),
    )
    span = TraceSpan(uuid4(), "tenant-a", uuid4(), "agent.execute", datetime.now(UTC))

    with pytest.raises(ValueError, match="completed"):
        sink.emit_span(span)


def test_otel_sink_records_metrics_without_high_cardinality_tenant_labels() -> None:
    meter = FakeMeter()
    sink = OpenTelemetryObservabilitySink(
        tracer=FakeTracer(),
        meter=meter,
        logger=FakeLogger(),
    )

    sink.emit_metric(MetricPoint("tenant-a", "agent.execution.duration", 12.5, "ms"))
    sink.emit_metric(MetricPoint("tenant-b", "agent.execution.duration", 20.0, "ms"))

    histogram = meter.histograms[("agent.execution.duration", "ms")]
    assert [record[0] for record in histogram.records] == [12.5, 20.0]
    assert all(record[1] is None for record in histogram.records)


def test_otel_sink_emits_tenant_bound_security_log_without_secret_payloads() -> None:
    logger = FakeLogger()
    sink = OpenTelemetryObservabilitySink(
        tracer=FakeTracer(),
        meter=FakeMeter(),
        logger=logger,
    )
    event = SecurityEvent(
        uuid4(),
        "tenant-a",
        "identity.token_revoked",
        "warning",
        datetime.now(UTC),
        actor_id="operator-1",
        trace_id="0123456789abcdef0123456789abcdef",
        run_id=uuid4(),
        outcome="deny",
    )

    sink.emit_security(event)

    record = logger.records[0]
    assert record["body"] == "identity.token_revoked"
    assert record["severity_text"] == "WARNING"
    assert record["attributes"]["platform.tenant_id"] == "tenant-a"
    assert record["attributes"]["platform.outcome"] == "deny"
    assert "token" not in record["attributes"]
