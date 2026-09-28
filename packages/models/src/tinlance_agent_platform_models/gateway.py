from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Protocol


@dataclass(frozen=True, slots=True)
class ModelRequest:
    tenant_id: str
    agent_id: str
    model: str
    messages: tuple[Mapping[str, str], ...]
    max_output_tokens: int = 4096
    trace_id: str | None = None

    def __post_init__(self) -> None:
        if not all((self.tenant_id, self.agent_id, self.model)):
            raise ValueError("tenant, agent and model are required")
        if any(value != value.strip() for value in (self.tenant_id, self.agent_id, self.model)):
            raise ValueError("tenant, agent and model must be normalized")
        if self.max_output_tokens < 1:
            raise ValueError("max_output_tokens must be positive")
        frozen = []
        for message in self.messages:
            role = message.get("role")
            content = message.get("content")
            if role not in {"system", "user", "assistant", "tool"}:
                raise ValueError("unsupported model message role")
            if not content:
                raise ValueError("model messages require content")
            frozen.append(MappingProxyType(dict(message)))
        object.__setattr__(self, "messages", tuple(frozen))


@dataclass(frozen=True, slots=True)
class ModelResponse:
    model: str
    output: str
    input_tokens: int = 0
    output_tokens: int = 0
    finish_reason: str = "stop"

    def __post_init__(self) -> None:
        if not self.model or not self.output:
            raise ValueError("model responses require model and output")
        if self.input_tokens < 0 or self.output_tokens < 0:
            raise ValueError("token usage cannot be negative")


class ModelProvider(Protocol):
    def complete(self, request: ModelRequest) -> ModelResponse: ...


class ModelGateway:
    def __init__(self) -> None:
        self._providers: dict[str, ModelProvider] = {}

    def register(self, name: str, provider: ModelProvider) -> None:
        if not name or name != name.strip() or name in self._providers:
            raise ValueError("model provider name must be unique and normalized")
        self._providers[name] = provider

    def complete(self, provider: str, request: ModelRequest) -> ModelResponse:
        selected = self._providers.get(provider)
        if selected is None:
            raise LookupError("model provider is not registered")
        return selected.complete(request)
