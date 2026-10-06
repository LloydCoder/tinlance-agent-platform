from uuid import uuid4

import pytest

from tinlance_agent_platform_contracts import (
    CapabilityRequest,
    DataClass,
    Principal,
    RequestContext,
    Reversibility,
    RiskTier,
    ToolCall,
)
from tinlance_agent_platform_tools import ToolGateway, ToolRegistration


class Reader:
    def execute(self, call: ToolCall) -> str:
        return f"ok:{call.resource}"


def request() -> CapabilityRequest:
    return CapabilityRequest(
        "read",
        "doc:1",
        frozenset({"doc:read"}),
        RiskTier.LOW,
        Reversibility.REVERSIBLE,
        DataClass.INTERNAL,
        "single",
    )


def test_tool_gateway_requires_platform_issued_single_use_permit() -> None:
    gateway = ToolGateway()
    gateway.register(ToolRegistration("reader", "doc:read", "reader"), Reader())
    principal = Principal("user", "human", "tenant-a", scopes=frozenset({"doc:read"}))
    context = RequestContext("req", "tenant-a", principal, "test")
    call = ToolCall(uuid4(), "tenant-a", uuid4(), "reader", "doc:read", "read", "doc:1")
    decision = gateway.authorize(context, call, request())
    permit = gateway.issue_permit(call, decision)
    assert gateway.execute(call, permit) == "ok:doc:1"
    with pytest.raises(PermissionError):
        gateway.execute(call, permit)


def test_tool_gateway_rejects_permit_for_different_call() -> None:
    gateway = ToolGateway()
    gateway.register(ToolRegistration("reader", "doc:read", "reader"), Reader())
    principal = Principal("user", "human", "tenant-a", scopes=frozenset({"doc:read"}))
    context = RequestContext("req", "tenant-a", principal, "test")
    call = ToolCall(uuid4(), "tenant-a", uuid4(), "reader", "doc:read", "read", "doc:1")
    decision = gateway.authorize(context, call, request())
    permit = gateway.issue_permit(call, decision)
    different = ToolCall(uuid4(), "tenant-a", call.run_id, "reader", "doc:read", "read", "doc:2")
    with pytest.raises(PermissionError):
        gateway.execute(different, permit)
