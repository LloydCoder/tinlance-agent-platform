from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol
from uuid import UUID

from tinlance_agent_platform_contracts import (
    CapabilityRequest,
    Decision,
    PolicyDecision,
    RequestContext,
)
from tinlance_agent_platform_kernel import assert_authority_boundary
from tinlance_agent_platform_policy import evaluate

_MAX_ARGUMENTS = 64


@dataclass(frozen=True, slots=True)
class ToolScope:
    tenant_id: str
    capability: str
    resource: str

    def __post_init__(self) -> None:
        if not all((self.tenant_id, self.capability, self.resource)):
            raise ValueError("complete tool scope is required")
        if any(
            value != value.strip()
            for value in (
                self.tenant_id,
                self.capability,
                self.resource,
            )
        ):
            raise ValueError("tool scope fields must be normalized")


@dataclass(frozen=True, slots=True)
class MCPTool:
    name: str
    description: str
    capability: str
    resource_pattern: str
    action: str = "call"

    def __post_init__(self) -> None:
        if not all((self.name, self.capability, self.action, self.resource_pattern)):
            raise ValueError("MCP tools require identity and resource scope")
        if any(
            value != value.strip()
            for value in (self.name, self.capability, self.action, self.resource_pattern)
        ):
            raise ValueError("MCP tool fields must be normalized")


class MCPTransport(Protocol):
    def call(
        self, tool_name: str, arguments: Mapping[str, object], scope: ToolScope
    ) -> dict[str, object]: ...


class ApprovalVerifier(Protocol):
    def require_approved_for(
        self,
        approval_id: UUID,
        tenant_id: str,
        run_id: UUID,
        action: str,
        resource: str,
    ) -> None: ...


class MCPToolGateway:
    def __init__(self, transport: MCPTransport) -> None:
        self._transport = transport
        self._tools: dict[str, MCPTool] = {}

    def register(self, tool: MCPTool) -> None:
        if tool.name in self._tools:
            raise ValueError("tool name must be unique and immutable")
        self._tools[tool.name] = tool

    def authorize(
        self,
        context: RequestContext,
        scope: ToolScope,
        tool_name: str,
        capability_request: CapabilityRequest,
    ) -> PolicyDecision:
        tool = self._tools.get(tool_name)
        if tool is None:
            raise LookupError("MCP tool is not registered")
        if scope.tenant_id != context.tenant_id:
            return PolicyDecision(
                Decision.DENY,
                "mcp-tenant-boundary",
                "1",
                "MCP tenant mismatch",
                capability_request.risk,
            )
        if (
            scope.capability != tool.capability
            or scope.resource != tool.resource_pattern
            or capability_request.action != tool.action
            or capability_request.resource != scope.resource
            or scope.capability not in capability_request.capabilities
        ):
            return PolicyDecision(
                Decision.DENY,
                "mcp-complete-mediation",
                "1",
                "MCP call does not match the governed capability request",
                capability_request.risk,
            )
        try:
            assert_authority_boundary(capability_request, context.principal)
        except PermissionError as exc:
            return PolicyDecision(
                Decision.DENY,
                "mcp-authorization",
                "1",
                str(exc),
                capability_request.risk,
            )
        return evaluate(capability_request)

    def call(
        self,
        context: RequestContext,
        scope: ToolScope,
        tool_name: str,
        arguments: Mapping[str, object],
        capability_request: CapabilityRequest,
        run_id: UUID,
        *,
        approval_id: UUID | None = None,
        approval_verifier: ApprovalVerifier | None = None,
    ) -> dict[str, object]:
        decision = self.authorize(context, scope, tool_name, capability_request)
        if decision.decision is Decision.DENY:
            raise PermissionError("MCP tool execution denied")
        if decision.requires_approval:
            if approval_id is None or approval_verifier is None:
                raise PermissionError("approved human review is required")
            approval_verifier.require_approved_for(
                approval_id,
                context.tenant_id,
                run_id,
                capability_request.action,
                capability_request.resource,
            )
        if len(arguments) > _MAX_ARGUMENTS:
            raise ValueError("MCP arguments are too large")
        return self._transport.call(
            tool_name,
            MappingProxyType(dict(arguments)),
            scope,
        )
