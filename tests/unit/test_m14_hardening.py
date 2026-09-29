from uuid import uuid4

import pytest

from tinlance_agent_platform_approvals import ApprovalService
from tinlance_agent_platform_contracts import (
    CapabilityRequest,
    DataClass,
    Decision,
    Principal,
    RequestContext,
    Reversibility,
    RiskTier,
    ToolCall,
)
from tinlance_agent_platform_tools import ToolGateway, ToolRegistration


def _request() -> CapabilityRequest:
    return CapabilityRequest(
        "delete",
        "db:item",
        frozenset({"db:delete"}),
        RiskTier.HIGH,
        Reversibility.IRREVERSIBLE,
        DataClass.INTERNAL,
        "single",
    )


def test_high_risk_tool_requires_bound_approval() -> None:
    class Executor:
        def execute(self, call: ToolCall) -> str:
            return "executed"

    gateway = ToolGateway()
    gateway.register(ToolRegistration("delete", "db:delete", "delete"), Executor())
    run_id = uuid4()
    call = ToolCall(uuid4(), "t1", run_id, "delete", "db:delete", "delete", "db:item")
    context = RequestContext(
        "r", "t1", Principal("u", "human", "t1", scopes=frozenset({"db:delete"})), "test"
    )
    decision = gateway.authorize(context, call, _request())
    assert decision.decision is Decision.REQUIRE_APPROVAL
    with pytest.raises(PermissionError):
        gateway.execute(call, decision)
    approvals = ApprovalService()
    approval = approvals.request("t1", run_id, "delete", "db:item", "destructive", "agent")
    approvals.decide(approval.approval_id, True, "t1", "approver-1")
    assert gateway.execute(call, decision, approval.approval_id, approvals) == "executed"


def test_approval_cannot_cross_tenant_or_resource() -> None:
    approvals = ApprovalService()
    approval = approvals.request("t1", uuid4(), "delete", "db:item", "destructive", "agent")
    with pytest.raises(PermissionError):
        approvals.decide(approval.approval_id, True, "t2")
