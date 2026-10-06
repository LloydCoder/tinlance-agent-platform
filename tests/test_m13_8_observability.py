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
        trace_id="0123456789abcdef0123456789abcdef",
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
    incident = correlator.start(
        "tenant-a", run_id=uuid4(), trace_id="0123456789abcdef0123456789abcdef"
    )
    security_id, audit_id = uuid4(), uuid4()
    correlator.add_security_event(incident.incident_id, security_id, tenant_id="tenant-a")
    correlator.add_audit(incident.incident_id, audit_id, tenant_id="tenant-a")
    result = correlator.get(incident.incident_id)
    assert result.security_event_ids == (security_id,)
    assert result.audit_ids == (audit_id,)


def test_correlation_context_rejects_blank_trace() -> None:
    context = CorrelationContext("tenant-a", uuid4(), trace_id=" ")
    with pytest.raises(ValueError):
        context.validate()


def test_incident_correlator_rejects_cross_tenant_correlation() -> None:
    correlator = IncidentCorrelator()
    incident = correlator.start("tenant-a")
    with pytest.raises(PermissionError):
        correlator.add_evidence(incident.incident_id, uuid4(), tenant_id="tenant-b")
    evidence_id = uuid4()
    correlator.add_evidence(incident.incident_id, evidence_id, tenant_id="tenant-a")
    assert correlator.get(incident.incident_id).evidence_ids == (evidence_id,)


def test_trace_rejects_non_w3c_identifier() -> None:
    with pytest.raises(ValueError):
        TraceSpan(
            uuid4(),
            "tenant-a",
            uuid4(),
            "run",
            datetime.now(UTC),
            trace_id="trace-1",
        )
