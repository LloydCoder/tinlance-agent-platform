from tinlance_agent_platform_observability import MetricPoint, InMemoryObservabilitySink, TraceSpan
from tinlance_agent_platform_observability.service import new_security_event
from uuid import uuid4


def test_observability_is_tenant_bound() -> None:
    sink = InMemoryObservabilitySink()
    sink.emit_metric(MetricPoint("t1", "tokens", 3, "count"))
    sink.emit_span(TraceSpan(uuid4(), "t1", uuid4(), "run", new_security_event("t1", "x", "info").occurred_at))
    assert sink.metrics[0].tenant_id == "t1"
    assert sink.spans[0].tenant_id == "t1"
