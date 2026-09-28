from uuid import uuid4

import pytest

from tinlance_agent_platform_contracts import (
    CapabilityRequest,
    DataClass,
    Principal,
    RequestContext,
    Reversibility,
    RiskTier,
)
from tinlance_agent_platform_mcp import MCPTool, MCPToolGateway, ToolScope


class FakeTransport:
    def call(
        self, tool_name: str, arguments: dict[str, object], scope: ToolScope
    ) -> dict[str, object]:
        return {"tool": tool_name, "tenant": scope.tenant_id, "ok": arguments.get("ok", True)}


def test_mcp_gateway_requires_complete_mediation() -> None:
    gateway = MCPToolGateway(FakeTransport())
    gateway.register(MCPTool("search", "search", "read", "repo:a", "read"))
    principal = Principal("u1", "human", "t1", scopes=frozenset({"read"}))
    context = RequestContext("req-1", "t1", principal, "test")
    request = CapabilityRequest(
        "read",
        "repo:a",
        frozenset({"read"}),
        RiskTier.LOW,
        Reversibility.REVERSIBLE,
        DataClass.INTERNAL,
        "single-resource",
    )
    result = gateway.call(
        context,
        ToolScope("t1", "read", "repo:a"),
        "search",
        {},
        request,
        run_id=uuid4(),
    )
    assert result["tenant"] == "t1"


def test_mcp_gateway_rejects_scope_or_authority_mismatch() -> None:
    gateway = MCPToolGateway(FakeTransport())
    gateway.register(MCPTool("search", "search", "read", "repo:a", "read"))
    principal = Principal("u1", "human", "t1", scopes=frozenset({"read"}))
    context = RequestContext("req-1", "t1", principal, "test")
    request = CapabilityRequest(
        "read",
        "repo:a",
        frozenset({"read"}),
        RiskTier.LOW,
        Reversibility.REVERSIBLE,
        DataClass.INTERNAL,
        "single-resource",
    )
    with pytest.raises(PermissionError):
        gateway.call(
            context,
            ToolScope("t1", "write", "repo:a"),
            "search",
            {},
            request,
            run_id=uuid4(),
        )
