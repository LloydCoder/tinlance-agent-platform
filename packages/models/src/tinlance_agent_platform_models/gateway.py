from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class ModelRequest:
    tenant_id: str
    agent_id: str
    model: str
    messages: tuple[dict[str, str], ...]
    max_output_tokens: int = 4096


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
        if request.max_output_tokens < 1:
            raise ValueError("max_output_tokens must be positive")
        return selected.complete(request)
