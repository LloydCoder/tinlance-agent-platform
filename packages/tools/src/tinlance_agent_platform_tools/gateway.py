from dataclasses import dataclass
from typing import Protocol
from tinlance_agent_platform_contracts import CapabilityRequest,Decision,PolicyDecision,RequestContext,ToolCall
from tinlance_agent_platform_kernel import assert_authority_boundary
from tinlance_agent_platform_policy import evaluate
@dataclass(frozen=True,slots=True)
class ToolRegistration:
    name:str; capability:str; description:str
class ToolExecutor(Protocol):
    def execute(self,call:ToolCall)->str: ...
class ToolGateway:
    def __init__(self)->None:self._tools:dict[str,tuple[ToolRegistration,ToolExecutor]]={}
    def register(self,registration:ToolRegistration,executor:ToolExecutor)->None:
        if registration.name in self._tools: raise ValueError("tool registration is immutable")
        self._tools[registration.name]=(registration,executor)
    def authorize(self,context:RequestContext,call:ToolCall,capability_request:CapabilityRequest)->PolicyDecision:
        if call.tenant_id!=context.tenant_id:return PolicyDecision(Decision.DENY,"tenant-boundary","1","tool tenant mismatch",capability_request.risk)
        try: assert_authority_boundary(capability_request,context.principal)
        except PermissionError as exc:return PolicyDecision(Decision.DENY,"authorization","1",str(exc),capability_request.risk)
        return evaluate(capability_request)
    def execute(self,call:ToolCall,decision:PolicyDecision)->str:
        if decision.decision is not Decision.ALLOW: raise PermissionError("tool execution denied or requires approval")
        registration=self._tools.get(call.tool_name)
        if registration is None or registration[0].capability!=call.capability: raise PermissionError("tool is not registered for requested capability")
        return registration[1].execute(call)
