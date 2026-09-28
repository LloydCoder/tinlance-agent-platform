import pytest

from tinlance_agent_platform_mcp import MCPTool, MCPToolGateway, ToolScope


class FakeTransport:
    def call(
        self, tool_name: str, arguments: dict[str, object], scope: ToolScope
    ) -> dict[str, object]:
        return {"tool": tool_name, "tenant": scope.tenant_id, "ok": arguments.get("ok", True)}


def test_mcp_gateway_requires_exact_scope() -> None:
    gateway = MCPToolGateway(FakeTransport())
    gateway.register(MCPTool("search", "search", "read", "repo:a"))
    scope = ToolScope("t1", "read", "repo:a")
    assert gateway.call(scope, "search", {})["tenant"] == "t1"
    with pytest.raises(PermissionError):
        gateway.call(ToolScope("t1", "write", "repo:a"), "search", {})
