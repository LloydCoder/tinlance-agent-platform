import json
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid4

from tinlance_agent_platform_contracts import (
    CapabilityRequest,
    Decision,
    PolicyDecision,
    RequestContext,
)
from tinlance_agent_platform_kernel import assert_authority_boundary
from tinlance_agent_platform_policy import evaluate

_MAX_ARGUMENTS = 64
_MAX_STRING = 16_384
_MAX_DEPTH = 8


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
class MCPExecutionPermit:
    _seal: object
    permit_id: UUID
    tool_name: str
    tenant_id: str
    run_id: UUID
    call_fingerprint: str
    decision: PolicyDecision
    intent_fingerprint: str | None = None


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


def _validate_value(value: object, depth: int = 0) -> None:
    if depth > _MAX_DEPTH:
        raise ValueError("MCP argument nesting exceeds safety limit")
    if isinstance(value, str):
        if len(value) > _MAX_STRING:
            raise ValueError("MCP string argument exceeds safety limit")
        return
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, Mapping):
        if len(value) > _MAX_ARGUMENTS:
            raise ValueError("MCP argument mapping exceeds safety limit")
        for key, nested in value.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("MCP argument keys must be non-empty strings")
            _validate_value(nested, depth + 1)
        return
    if isinstance(value, (list, tuple)):
        if len(value) > _MAX_ARGUMENTS:
            raise ValueError("MCP argument sequence exceeds safety limit")
        for nested in value:
            _validate_value(nested, depth + 1)
        return
    raise TypeError("unsupported MCP argument type")


class ApprovalVerifier(Protocol):
    def require_approved_for(
        self,
        approval_id: UUID,
        tenant_id: str,
        run_id: UUID,
        action: str,
        resource: str,
        *,
        intent_fingerprint: str | None = None,
    ) -> None: ...


class MCPToolGateway:
    def __init__(self, transport: MCPTransport) -> None:
        self._transport = transport
        self._tools: dict[str, MCPTool] = {}
        self._permit_seal = object()
        self._used_permits: set[UUID] = set()

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

    @staticmethod
    def _call_fingerprint(
        tenant_id: str,
        run_id: UUID,
        tool_name: str,
        scope: ToolScope,
        capability_request: CapabilityRequest,
        arguments: Mapping[str, object],
    ) -> str:
        payload = json.dumps(
            {
                "tenant_id": tenant_id,
                "run_id": str(run_id),
                "tool_name": tool_name,
                "capability": scope.capability,
                "resource": scope.resource,
                "action": capability_request.action,
                "request_resource": capability_request.resource,
                "arguments": arguments,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return sha256(payload.encode("utf-8")).hexdigest()

    def issue_permit(
        self,
        *,
        tenant_id: str,
        run_id: UUID,
        tool_name: str,
        scope: ToolScope,
        capability_request: CapabilityRequest,
        arguments: Mapping[str, object],
        decision: PolicyDecision,
        intent_fingerprint: str | None = None,
    ) -> MCPExecutionPermit:
        if decision.decision is Decision.DENY or (
            decision.decision is Decision.REQUIRE_AUTHORIZATION and not decision.requires_approval
        ):
            raise PermissionError("MCP tool execution denied")
        return MCPExecutionPermit(
            self._permit_seal,
            uuid4(),
            tool_name,
            tenant_id,
            run_id,
            self._call_fingerprint(
                tenant_id, run_id, tool_name, scope, capability_request, arguments
            ),
            decision,
            intent_fingerprint,
        )

    def execute(
        self,
        *,
        permit: MCPExecutionPermit,
        scope: ToolScope,
        capability_request: CapabilityRequest,
        arguments: Mapping[str, object],
        approval_id: UUID | None = None,
        approval_verifier: ApprovalVerifier | None = None,
    ) -> dict[str, object]:
        if permit._seal is not self._permit_seal:
            raise PermissionError("MCP execution permit is not platform-issued")
        if permit.tenant_id != scope.tenant_id or permit.tool_name not in self._tools:
            raise PermissionError("MCP execution permit scope mismatch")
        fingerprint = self._call_fingerprint(
            permit.tenant_id,
            permit.run_id,
            permit.tool_name,
            scope,
            capability_request,
            arguments,
        )
        if permit.call_fingerprint != fingerprint:
            raise PermissionError("MCP execution permit intent mismatch")
        if permit.permit_id in self._used_permits:
            raise PermissionError("MCP execution permit has already been consumed")
        if permit.decision.decision is Decision.DENY or (
            permit.decision.decision is Decision.REQUIRE_AUTHORIZATION
            and not permit.decision.requires_approval
        ):
            raise PermissionError("MCP tool execution denied")
        if permit.decision.requires_approval:
            if approval_id is None or approval_verifier is None:
                raise PermissionError("approved human review is required")
            approval_verifier.require_approved_for(
                approval_id,
                permit.tenant_id,
                permit.run_id,
                capability_request.action,
                capability_request.resource,
                intent_fingerprint=permit.intent_fingerprint,
            )
        _validate_value(arguments)
        try:
            return self._transport.call(
                permit.tool_name,
                MappingProxyType(dict(arguments)),
                scope,
            )
        finally:
            self._used_permits.add(permit.permit_id)

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
        intent_fingerprint: str | None = None,
    ) -> dict[str, object]:
        decision = self.authorize(context, scope, tool_name, capability_request)
        permit = self.issue_permit(
            tenant_id=context.tenant_id,
            run_id=run_id,
            tool_name=tool_name,
            scope=scope,
            capability_request=capability_request,
            arguments=arguments,
            decision=decision,
            intent_fingerprint=intent_fingerprint,
        )
        return self.execute(
            permit=permit,
            scope=scope,
            capability_request=capability_request,
            arguments=arguments,
            approval_id=approval_id,
            approval_verifier=approval_verifier,
        )

