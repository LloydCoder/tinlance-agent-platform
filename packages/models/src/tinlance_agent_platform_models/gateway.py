from dataclasses import dataclass
from typing import Protocol
from tinlance_agent_platform_contracts import ToolCall
@dataclass(frozen=True, slots=True)
class ModelRequest:
    tenant_id:str; agent_id:str; model:str; messages:tuple[dict[str,str],...]; max_output_tokens:int=4096
    def __post_init__(self)->None:
        if not self.tenant_id or not self.agent_id or not self.model or not self.messages or self.max_output_tokens<1: raise ValueError("invalid model request")
        if any(m.get("role") not in {"system","user","assistant","tool"} for m in self.messages): raise ValueError("unsupported model message role")
@dataclass(frozen=True, slots=True)
class ModelResponse:
    model:str; output:str; input_tokens:int=0; output_tokens:int=0; finish_reason:str="stop"; tool_calls:tuple[ToolCall,...]=()
    def __post_init__(self)->None:
        if self.input_tokens<0 or self.output_tokens<0: raise ValueError("token counts cannot be negative")
class ModelProvider(Protocol):
    def complete(self,request:ModelRequest)->ModelResponse: ...
class ModelGateway:
    def __init__(self)->None: self._providers:dict[str,ModelProvider]={}
    def register(self,name:str,provider:ModelProvider)->None:
        if not name or name in self._providers: raise ValueError("model provider name must be unique and non-empty")
        self._providers[name]=provider
    def complete(self,provider:str,request:ModelRequest)->ModelResponse:
        selected=self._providers.get(provider)
        if selected is None: raise LookupError("model provider is not registered")
        response=selected.complete(request)
        if any(call.tenant_id!=request.tenant_id for call in response.tool_calls): raise PermissionError("model returned a cross-tenant tool call")
        return response
