from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Protocol


@dataclass(frozen=True, slots=True)
class ToolScope:
    tenant_id: str
    capability: str
    resource: str

    def __post_init__(self) -> None:
        if not all((self.tenant_id, self.capability, self.resource)):
            raise ValueError("complete tool scope is required")
        if any(value != value.strip() for value in (self.tenant_id, self.capability, self.resource)):
            raise ValueError("tool scope fields must be normalized")


@dataclass(frozen=True, slots=True)
class MCPTool:
    name: str
    description: str
    capability: str
    resource_pattern: str

    def __post_init__(self) -> None:
        if not all((self.name, self.capability, self.resource_pattern)):
            raise ValueError("MCP tools require identity and resource scope")
        if any(value != value.strip() for value in (self.name, self.capability, self.resource_pattern)):
            raise ValueError("MCP tool fields must be normalized")


class MCPTransport(Protocol):
    def call(
        self, tool_name: str, arguments: Mapping[str, object], scope: ToolScope
    ) -> dict[str, object]: ...


class MCPToolGateway:
    def __init__(self, transport: MCPTransport) -> None:
        self._transport = transport
        self._tools: dict[str, MCPTool] = {}

    def register(self, tool: MCPTool) -> None:
        if tool.name in self._tools:
            raise ValueError("tool name must be unique and immutable")
        self._tools[tool.name] = tool

    def call(
        self, scope: ToolScope, tool_name: str, arguments: Mapping[str, object]
    ) -> dict[str, object]:
        tool = self._tools.get(tool_name)
        if tool is None:
            raise LookupError("MCP tool is not registered")
        if scope.capability != tool.capability or scope.resource != tool.resource_pattern:
            raise PermissionError("MCP scope does not match registered tool")
        return self._transport.call(tool_name, MappingProxyType(dict(arguments)), scope)
