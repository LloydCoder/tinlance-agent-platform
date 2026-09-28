from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class ModelRequest:
    tenant_id: str
    agent_id: str
    model: str
    messages: tuple[dict[str, str], ...]
    max_output_tokens: int = 4096
    trace_id: str | None = None

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.agent_id or not self.model:
            raise ValueError("tenant, agent and model are required")
        if self.max_output_tokens < 1:
            raise ValueError("max_output_tokens must be positive")
        for message in self.messages:
            if message.get("role") not in {"system", "user", "assistant", "tool"}:
                raise ValueError("unsupported model message role")
            if not message.get("content"):
                raise ValueError("model messages require content")


@dataclass(frozen=True, slots=True)
class ModelResponse:
    model: str
    output: str
    input_tokens: int = 0
    output_tokens: int = 0
    finish_reason: str = "stop"


class ModelProvider(Protocol):
    def complete(self, request: ModelRequest) -> ModelResponse: ...


class ModelGateway:
    def __init__(self) -> None:
        self._providers: dict[str, ModelProvider] = {}

    def register(self, name: str, provider: ModelProvider) -> None:
        if not name or name in self._providers:
            raise ValueError("model provider name must be unique and non-empty")
        self._providers[name] = provider

    def complete(self, provider: str, request: ModelRequest) -> ModelResponse:
        selected = self._providers.get(provider)
        if selected is None:
            raise LookupError("model provider is not registered")
        response = selected.complete(request)
        if response.input_tokens < 0 or response.output_tokens < 0:
            raise ValueError("provider returned negative token usage")
        return response
