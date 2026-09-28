from uuid import uuid4

from tinlance_agent_platform_observability import (
    InMemoryObservabilitySink,
    MetricPoint,
    TraceSpan,
)
from tinlance_agent_platform_observability.service import new_security_event


def test_observability_is_tenant_bound() -> None:
    sink = InMemoryObservabilitySink()
    event = new_security_event("t1", "x", "info")
    sink.emit_metric(MetricPoint("t1", "tokens", 3, "count"))
    sink.emit_span(TraceSpan(uuid4(), "t1", uuid4(), "run", event.occurred_at))
    assert sink.metrics[0].tenant_id == "t1"
    assert sink.spans[0].tenant_id == "t1"
