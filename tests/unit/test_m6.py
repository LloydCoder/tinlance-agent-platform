import pytest
from uuid import uuid4

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


def request() -> CapabilityRequest:
    return CapabilityRequest(
        "read",
        "repo:a",
        frozenset({"read"}),
        RiskTier.LOW,
        Reversibility.REVERSIBLE,
        DataClass.INTERNAL,
        "single-resource",
    )


def context() -> RequestContext:
    principal = Principal("u1", "human", "t1", scopes=frozenset({"read"}))
    return RequestContext("req-1", "t1", principal, "test")


def test_mcp_gateway_requires_governed_scope() -> None:
    gateway = MCPToolGateway(FakeTransport())
    gateway.register(MCPTool("search", "search", "read", "read", "repo:a"))
    scope = ToolScope("t1", "read", "repo:a")
    run_id = uuid4()
    result = gateway.call(context(), scope, "search", {}, request(), run_id=run_id)
    assert result["tenant"] == "t1"


def test_mcp_gateway_rejects_scope_or_authority_mismatch() -> None:
    gateway = MCPToolGateway(FakeTransport())
    gateway.register(MCPTool("search", "search", "read", "read", "repo:a"))
    with pytest.raises(PermissionError):
        gateway.call(
            context(),
            ToolScope("t1", "write", "repo:a"),
            "search",
            {},
            request(),
            run_id=uuid4(),
        )
