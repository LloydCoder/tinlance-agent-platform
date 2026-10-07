from datetime import UTC, datetime
from uuid import uuid4

import pytest

from tinlance_agent_platform_contracts import (
    CapabilityRequest,
    DataClass,
    Decision,
    PolicyDecision,
    Principal,
    RequestContext,
    Reversibility,
    RiskTier,
)
from tinlance_agent_platform_evidence import InMemoryAuditStore, InMemoryEvidenceStore
from tinlance_agent_platform_mcp import MCPTool, MCPToolGateway, ToolScope
from tinlance_agent_platform_observability import IncidentCorrelator, new_security_event


def _capability() -> CapabilityRequest:
    return CapabilityRequest(
        "read",
        "doc:1",
        frozenset({"doc:read"}),
        RiskTier.LOW,
        Reversibility.REVERSIBLE,
        DataClass.INTERNAL,
        "single",
    )


class Transport:
    def __init__(self) -> None:
        self.calls = 0

    def call(self, tool_name, arguments, scope):
        self.calls += 1
        return {"tool": tool_name, "ok": True}


def test_mcp_permit_is_single_use_and_intent_bound() -> None:
    transport = Transport()
    gateway = MCPToolGateway(transport)
    gateway.register(MCPTool("reader", "read docs", "doc:read", "doc:1", "read"))
    principal = Principal("user", "human", "tenant-a", scopes=frozenset({"doc:read"}))
    context = RequestContext("req", "tenant-a", principal, "test")
    scope = ToolScope("tenant-a", "doc:read", "doc:1")
    args = {"id": "1"}
    decision = gateway.authorize(context, scope, "reader", _capability())
    permit = gateway.issue_permit(
        tenant_id="tenant-a",
        run_id=uuid4(),
        tool_name="reader",
        scope=scope,
        capability_request=_capability(),
        arguments=args,
        decision=decision,
    )
    gateway.execute(
        permit=permit,
        scope=scope,
        capability_request=_capability(),
        arguments=args,
    )
    with pytest.raises(PermissionError):
        gateway.execute(
            permit=permit,
            scope=scope,
            capability_request=_capability(),
            arguments={"id": "2"},
        )
    assert transport.calls == 1


def test_mcp_unresolved_authorization_fails_closed() -> None:
    transport = Transport()
    gateway = MCPToolGateway(transport)
    gateway.register(MCPTool("reader", "read docs", "doc:read", "doc:1", "read"))
    decision = PolicyDecision(
        Decision.REQUIRE_AUTHORIZATION,
        "test",
        "1",
        "approval",
        RiskTier.LOW,
        requires_approval=False,
    )
    with pytest.raises(PermissionError):
        gateway.issue_permit(
            tenant_id="tenant-a",
            run_id=uuid4(),
            tool_name="reader",
            scope=ToolScope("tenant-a", "doc:read", "doc:1"),
            capability_request=_capability(),
            arguments={"id": "1"},
            decision=decision,
        )


def test_evidence_and_audit_hashes_commit_record_identity() -> None:
    run_id = uuid4()
    evidence = InMemoryEvidenceStore()
    first = evidence.append("tenant-a", run_id, "same", occurred_at=datetime.now(UTC))
    second = evidence.append("tenant-a", run_id, "same", occurred_at=first.occurred_at)
    assert first.record_hash != second.record_hash
    assert evidence.verify("tenant-a", run_id)

    audit = InMemoryAuditStore()
    first_audit = audit.append("tenant-a", run_id, "actor", "read", "doc", "allow")
    second_audit = audit.append(
        "tenant-a", run_id, "actor", "read", "doc", "allow", first_audit.occurred_at
    )
    assert first_audit.record_hash != second_audit.record_hash
    assert audit.verify("tenant-a", run_id)


def test_security_event_rejects_malformed_trace_id() -> None:
    with pytest.raises(ValueError):
        new_security_event("tenant-a", "auth.denied", "warning", trace_id="not-w3c")


def test_incident_rejects_malformed_trace_id() -> None:
    with pytest.raises(ValueError):
        IncidentCorrelator().start("tenant-a", trace_id="not-w3c")
