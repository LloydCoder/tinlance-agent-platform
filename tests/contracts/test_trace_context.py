from uuid import uuid4

import pytest

from tinlance_agent_platform_contracts import (
    ApprovalRequest,
    EvidenceLink,
    Principal,
    RequestContext,
    ToolCall,
    TraceEvidenceRef,
    TraceLineageContext,
)


def make_context(**overrides):
    values = {
        "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
        "span_id": "00f067aa0ba902b7",
        "correlation_id": "corr-1",
        "request_id": "req-1",
        "tenant_id": "tenant-a",
        "operation": "platform.execute",
        "started_at": "2026-10-18T05:00:00Z",
        "safe_attributes": (("service", "platform"), ("outcome", "started"), ("attempt", 0)),
    }
    values.update(overrides)
    return TraceLineageContext(**values)


def test_lineage_preserves_authority_relevant_correlation_and_evidence_digest():
    evidence = TraceEvidenceRef(
        evidence_id="evidence:policy:1", kind="policy-decision", sha256="a" * 64
    )
    payload = make_context(evidence_refs=(evidence,), decision_id="decision-1").as_payload()
    assert payload["schema_version"] == "trace-context/v1"
    assert payload["tenant_id"] == "tenant-a"
    assert payload["decision_id"] == "decision-1"
    assert payload["evidence_refs"][0]["sha256"] == "a" * 64
    assert "authorization" not in payload


def test_child_span_keeps_trace_and_tenant_lineage():
    child = make_context().child(
        span_id="1111111111111111",
        operation="platform.policy.evaluate",
        started_at="2026-10-18T05:00:02Z",
    )
    assert child.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert child.parent_span_id == "00f067aa0ba902b7"
    assert child.tenant_id == "tenant-a"
    assert child.as_headers()["traceparent"] == "00-4bf92f3577b34da6a3ce929d0e0e4736-1111111111111111-00"


@pytest.mark.parametrize(
    "overrides",
    [
        {"trace_id": "0" * 32},
        {"span_id": "0" * 16},
        {"parent_span_id": "not-a-span"},
        {"started_at": "2026-10-18T05:00:00"},
        {"data_classification": "top-secret"},
        {"safe_attributes": (("authorization", "Bearer abc"),)},
    ],
)
def test_invalid_trace_or_sensitive_attributes_fail_closed(overrides):
    with pytest.raises(ValueError):
        make_context(**overrides)


def test_evidence_digest_must_be_sha256():
    with pytest.raises(ValueError, match="SHA-256"):
        TraceEvidenceRef(evidence_id="evidence:1", kind="tool-output", sha256="bad")



def test_request_approval_tool_and_evidence_models_bind_trace_tenant():
    context = make_context()
    principal = Principal(subject_id="subject-1", principal_type="user", tenant_id="tenant-a")
    request = RequestContext(
        request_id="req-1",
        tenant_id="tenant-a",
        principal=principal,
        environment="test",
        trace_id=context.trace_id,
        trace_context=context,
    )
    approval = ApprovalRequest(
        approval_id=uuid4(), tenant_id="tenant-a", run_id=uuid4(),
        action="tool.execute", resource="resource:1", reason="policy requires approval",
        requested_by="subject-1", trace_context=context,
    )
    tool_call = ToolCall(
        call_id=uuid4(), tenant_id="tenant-a", run_id=uuid4(), tool_name="search",
        capability="search", action="read", resource="resource:1", trace_context=context,
    )
    evidence_link = EvidenceLink(
        tenant_id="tenant-a", run_id=uuid4(), action_id=uuid4(),
        evidence_id=uuid4(), sequence=1, trace_context=context,
    )
    assert request.trace_context is context
    assert approval.trace_context is context
    assert tool_call.trace_context is context
    assert evidence_link.trace_context is context


def test_request_and_audit_lineage_rejects_cross_tenant_context():
    context = make_context()
    principal = Principal(subject_id="subject-2", principal_type="user", tenant_id="tenant-b")
    with pytest.raises(ValueError, match="lineage must match"):
        RequestContext(
            request_id="req-1", tenant_id="tenant-b", principal=principal,
            environment="test", trace_id=context.trace_id, trace_context=context,
        )
