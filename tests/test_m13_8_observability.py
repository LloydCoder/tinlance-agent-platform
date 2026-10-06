from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from tinlance_agent_platform_observability import (
    CorrelationContext,
    IncidentCorrelator,
    SecurityEvent,
    TraceSpan,
)


def test_security_event_carries_execution_correlation() -> None:
    event = SecurityEvent(
        uuid4(),
        "tenant-a",
        "tool.denied",
        "warning",
        datetime.now(UTC),
        actor_id="agent-a",
        trace_id="trace-1",
        run_id=uuid4(),
        execution_id=uuid4(),
        outcome="deny",
    )
    assert event.run_id is not None
    assert event.execution_id is not None


def test_trace_rejects_invalid_time_order() -> None:
    start = datetime.now(UTC)
    with pytest.raises(ValueError):
        TraceSpan(uuid4(), "tenant-a", uuid4(), "run", start, start - timedelta(seconds=1))


def test_incident_correlator_binds_security_and_audit() -> None:
    correlator = IncidentCorrelator()
    incident = correlator.start("tenant-a", run_id=uuid4(), trace_id="trace-1")
    security_id, audit_id = uuid4(), uuid4()
    correlator.add_security_event(incident.incident_id, security_id)
    correlator.add_audit(incident.incident_id, audit_id)
    result = correlator.get(incident.incident_id)
    assert result.security_event_ids == (security_id,)
    assert result.audit_ids == (audit_id,)


def test_correlation_context_rejects_blank_trace() -> None:
    context = CorrelationContext("tenant-a", uuid4(), trace_id=" ")
    with pytest.raises(ValueError):
        context.validate()
