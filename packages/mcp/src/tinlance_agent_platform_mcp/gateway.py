from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Protocol
from uuid import UUID
from tinlance_agent_platform_contracts import CapabilityRequest,Decision,RequestContext,ToolCall
@dataclass(frozen=True,slots=True)
class ToolScope:
    tenant_id:str; capability:str; resource:str
@dataclass(frozen=True,slots=True)
class MCPTool:
    name:str; description:str; capability:str; resource_pattern:str; requires_approval:bool=False
class MCPTransport(Protocol):
    def call(self,tool_name:str,arguments:dict[str,object])->dict[str,object]: ...
class MCPAuthorizer(Protocol):
    def authorize(self,context:RequestContext,request:CapabilityRequest): ...
class MCPApprovalVerifier(Protocol):
    def require_approved_for(self,approval_id:UUID,tenant_id:str,run_id:UUID,action:str,resource:str)->None: ...
class MCPToolGateway:
    def __init__(self,transport:MCPTransport)->None: self._transport=transport; self._tools:dict[str,MCPTool]={}
    def register(self,tool:MCPTool)->None:
        if not tool.name or tool.name in self._tools or not tool.capability or not tool.resource_pattern: raise ValueError("invalid MCP tool registration")
        self._tools[tool.name]=tool
    def call(self,scope:ToolScope,tool_name:str,arguments:dict[str,object])->dict[str,object]:
        tool=self._tools.get(tool_name)
        if tool is None: raise LookupError("MCP tool is not registered")
        if scope.capability!=tool.capability or not fnmatchcase(scope.resource,tool.resource_pattern): raise PermissionError("MCP scope does not match registered tool")
        if scope.tenant_id=="": raise PermissionError("MCP tenant is required")
        return self._transport.call(tool_name,dict(arguments))
    def governed_call(self,context:RequestContext,call:ToolCall,capability_request:CapabilityRequest,authorizer:MCPAuthorizer,approval_id:UUID|None=None,approval_verifier:MCPApprovalVerifier|None=None,arguments:dict[str,object]|None=None)->dict[str,object]:
        tool=self._tools.get(call.tool_name)
        if tool is None: raise LookupError("MCP tool is not registered")
        if call.tenant_id!=context.tenant_id or call.capability!=tool.capability or not fnmatchcase(call.resource,tool.resource_pattern): raise PermissionError("MCP authorization boundary mismatch")
        decision=authorizer.authorize(context,capability_request)
        if decision.decision is Decision.DENY: raise PermissionError("MCP tool call denied")
        if tool.requires_approval or decision.requires_approval:
            if approval_id is None or approval_verifier is None: raise PermissionError("approved human review is required")
            approval_verifier.require_approved_for(approval_id,call.tenant_id,call.run_id,call.action,call.resource)
        return self._transport.call(call.tool_name,dict(arguments or {}))
