from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol


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
            raise ValueError("model request identifiers must be normalized")
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


@dataclass(frozen=True, slots=True)
class _ProviderBinding:
    provider: ModelProvider
    tenants: frozenset[str] | None
    agents: frozenset[str] | None


class ModelGateway:
    """Provider-neutral model boundary with explicit tenant and agent allowlists."""

    def __init__(self) -> None:
        self._providers: dict[str, _ProviderBinding] = {}

    def register(
        self,
        name: str,
        provider: ModelProvider,
        *,
        tenants: frozenset[str] | None = None,
        agents: frozenset[str] | None = None,
    ) -> None:
        if not name or name != name.strip() or name in self._providers:
            raise ValueError("model provider name must be unique and normalized")
        if tenants is not None and any(
            not tenant or tenant != tenant.strip() for tenant in tenants
        ):
            raise ValueError("model tenant allowlist must be normalized")
        if agents is not None and any(
            not agent or agent != agent.strip() for agent in agents
        ):
            raise ValueError("model agent allowlist must be normalized")
        self._providers[name] = _ProviderBinding(provider, tenants, agents)

    def complete(self, provider: str, request: ModelRequest) -> ModelResponse:
        binding = self._providers.get(provider)
        if binding is None:
            raise LookupError("model provider is not registered")
        if binding.tenants is not None and request.tenant_id not in binding.tenants:
            raise PermissionError("model provider is not enabled for this tenant")
        if binding.agents is not None and request.agent_id not in binding.agents:
            raise PermissionError("model provider is not enabled for this agent")
        response = binding.provider.complete(request)
        if response.model != request.model:
            raise ValueError("model provider returned an unexpected model")
        if response.output_tokens > request.max_output_tokens:
            raise ValueError("model provider exceeded the requested output-token budget")
        return response
