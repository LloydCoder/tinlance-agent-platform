from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from tinlance_agent_platform_contracts import (
    CapabilityRequest,
    Decision,
    PolicyDecision,
    RequestContext,
    RiskTier,
    ToolCall,
)
from tinlance_agent_platform_kernel import assert_authority_boundary
from tinlance_agent_platform_policy import evaluate


@dataclass(frozen=True, slots=True)
class ToolRegistration:
    name: str
    capability: str
    description: str
    version: str = "1"
    risk: RiskTier | None = None
    sandbox_required: bool = False
    timeout_seconds: float = 300.0
    max_tool_calls: int = 1
    evidence_required: bool = True
    secret_required: bool = False

    def __post_init__(self) -> None:
        if not self.name.strip() or not self.capability.strip() or not self.description.strip():
            raise ValueError("tool registration requires name, capability, and description")
        if not self.version.strip() or self.timeout_seconds <= 0 or self.max_tool_calls < 1:
            raise ValueError("tool registration limits must be valid")


class ToolExecutor(Protocol):
    def execute(self, call: ToolCall) -> str: ...


class TimedToolExecutor(Protocol):
    def execute_with_timeout(self, call: ToolCall, timeout_seconds: float) -> str: ...


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


class ToolGateway:
    def __init__(self) -> None:
        self._tools: dict[str, tuple[ToolRegistration, ToolExecutor]] = {}

    def register(self, registration: ToolRegistration, executor: ToolExecutor) -> None:
        if registration.name in self._tools:
            raise ValueError("tool registration is immutable")
        self._tools[registration.name] = (registration, executor)

    def supports_hard_timeout(self, name: str) -> bool:
        item = self._tools.get(name)
        return item is not None and hasattr(item[1], "execute_with_timeout")

    def registration(self, name: str) -> ToolRegistration:
        item = self._tools.get(name)
        if item is None:
            raise KeyError("tool is not registered")
        return item[0]

    def authorize(
        self,
        context: RequestContext,
        call: ToolCall,
        capability_request: CapabilityRequest,
    ) -> PolicyDecision:
        if call.tenant_id != context.tenant_id:
            return PolicyDecision(
                Decision.DENY,
                "tenant-boundary",
                "2",
                "tool tenant mismatch",
                capability_request.risk,
            )
        if (
            call.capability not in capability_request.capabilities
            or call.action != capability_request.action
            or call.resource != capability_request.resource
        ):
            return PolicyDecision(
                Decision.DENY,
                "complete-mediation",
                "2",
                "tool call does not match the authorized capability request",
                capability_request.risk,
            )
        try:
            assert_authority_boundary(capability_request, context.principal)
        except PermissionError as exc:
            return PolicyDecision(
                Decision.DENY, "authorization", "2", str(exc), capability_request.risk
            )
        return evaluate(capability_request)

    def execute(
        self,
        call: ToolCall,
        decision: PolicyDecision,
        approval_id: UUID | None = None,
        approval_verifier: ApprovalVerifier | None = None,
        *,
        intent_fingerprint: str | None = None,
        timeout_seconds: float | None = None,
    ) -> str:
        if decision.decision is Decision.DENY:
            raise PermissionError("tool execution denied")
        if decision.requires_approval:
            if approval_id is None or approval_verifier is None:
                raise PermissionError("approved human review is required")
            approval_verifier.require_approved_for(
                approval_id,
                call.tenant_id,
                call.run_id,
                call.action,
                call.resource,
                intent_fingerprint=intent_fingerprint,
            )
        registration = self._tools.get(call.tool_name)
        if registration is None or registration[0].capability != call.capability:
            raise PermissionError("tool is not registered for requested capability")
        executor = registration[1]
        if timeout_seconds is not None and hasattr(executor, "execute_with_timeout"):
            return executor.execute_with_timeout(call, timeout_seconds)  # type: ignore[attr-defined]
        return executor.execute(call)
