from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class ToolScope:
    tenant_id: str
    capability: str
    resource: str


@dataclass(frozen=True, slots=True)
class MCPTool:
    name: str
    description: str
    capability: str
    resource_pattern: str


class MCPTransport(Protocol):
    def call(self, tool_name: str, arguments: dict[str, object]) -> dict[str, object]: ...


class MCPToolGateway:
    def __init__(self, transport: MCPTransport) -> None:
        self._transport = transport
        self._tools: dict[str, MCPTool] = {}

    def register(self, tool: MCPTool) -> None:
        if not tool.name or tool.name in self._tools:
            raise ValueError("tool name must be unique and non-empty")
        self._tools[tool.name] = tool

    def call(
        self, scope: ToolScope, tool_name: str, arguments: dict[str, object]
    ) -> dict[str, object]:
        tool = self._tools.get(tool_name)
        if tool is None:
            raise LookupError("MCP tool is not registered")
        if scope.capability != tool.capability or scope.resource != tool.resource_pattern:
            raise PermissionError("MCP scope does not match registered tool")
        return self._transport.call(tool_name, dict(arguments))
