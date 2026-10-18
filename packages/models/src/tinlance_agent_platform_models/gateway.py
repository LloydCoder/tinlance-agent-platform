import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol
from uuid import uuid4

_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")


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
        if agents is not None and any(not agent or agent != agent.strip() for agent in agents):
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


@dataclass(frozen=True, slots=True)
class ModelRoute:
    """Immutable, reviewed route metadata; it never grants execution authority."""

    route_id: str
    provider: str
    model: str
    policy_version: str
    capabilities: frozenset[str]
    task_policies: frozenset[str]
    data_classifications: frozenset[str]
    risk_classes: frozenset[str]
    max_risk_score: int
    max_cost_microusd: int
    priority: int = 100
    tenants: frozenset[str] | None = None
    agents: frozenset[str] | None = None
    enabled: bool = True

    def __post_init__(self) -> None:
        for value, name in (
            (self.route_id, "route_id"),
            (self.provider, "provider"),
            (self.model, "model"),
            (self.policy_version, "policy_version"),
        ):
            if not value or value != value.strip():
                raise ValueError(f"{name} must be normalized and non-empty")
        if not self.capabilities or any(
            not item or item != item.strip() for item in self.capabilities
        ):
            raise ValueError("route capabilities must be normalized and non-empty")
        if not self.task_policies or any(
            not item or item != item.strip() for item in self.task_policies
        ):
            raise ValueError("route task policies must be normalized and non-empty")
        if not self.data_classifications or not self.data_classifications <= {
            "public",
            "internal",
            "confidential",
            "restricted",
        }:
            raise ValueError("route data classifications are invalid")
        if not self.risk_classes or not self.risk_classes <= {
            "low",
            "moderate",
            "high",
            "critical",
        }:
            raise ValueError("route risk classes are invalid")
        if not 0 <= self.max_risk_score <= 100 or self.max_cost_microusd < 0:
            raise ValueError("route risk and cost limits are invalid")
        for allowlist in (self.tenants, self.agents):
            if allowlist is not None and any(
                not value or value != value.strip() for value in allowlist
            ):
                raise ValueError("route allowlists must contain normalized identifiers")


@dataclass(frozen=True, slots=True)
class ModelRoutingRequest:
    tenant_id: str
    agent_id: str
    task_policy: str
    model_capability: str
    risk_class: str
    data_classification: str
    risk_score: int
    budget_microusd: int
    provider_availability: frozenset[str]
    trace_id: str | None = None

    def __post_init__(self) -> None:
        for value, name in (
            (self.tenant_id, "tenant_id"),
            (self.agent_id, "agent_id"),
            (self.task_policy, "task_policy"),
            (self.model_capability, "model_capability"),
        ):
            if not value or value != value.strip():
                raise ValueError(f"{name} must be normalized and non-empty")
        if self.risk_class not in {"low", "moderate", "high", "critical"}:
            raise ValueError("unsupported risk class")
        if self.data_classification not in {"public", "internal", "confidential", "restricted"}:
            raise ValueError("unsupported data classification")
        if not 0 <= self.risk_score <= 100 or self.budget_microusd < 0:
            raise ValueError("routing risk and budget are invalid")
        if not self.provider_availability:
            raise ValueError("provider availability must be explicitly supplied")
        if any(
            not provider or provider != provider.strip() for provider in self.provider_availability
        ):
            raise ValueError("available provider names must be normalized")
        if self.trace_id is not None and (
            not _TRACE_ID.fullmatch(self.trace_id) or set(self.trace_id) == {"0"}
        ):
            raise ValueError("trace_id must be a valid non-zero W3C trace identifier")


@dataclass(frozen=True, slots=True)
class ModelRoutingDecision:
    decision_id: str
    allowed: bool
    route: str | None
    provider: str | None
    model_id: str | None
    task_policy: str
    policy_version: str | None
    reason_code: str
    trace_id: str | None

    @property
    def route_id(self) -> str | None:
        return self.route

    @property
    def model(self) -> str | None:
        return self.model_id


class ModelRouter:
    """Deterministic, policy-constrained route selector with fail-closed audit."""

    def __init__(
        self,
        record_decision: Callable[[ModelRoutingDecision], None],
        verify_registered_route: Callable[[ModelRoute], bool],
    ) -> None:
        if not callable(record_decision):
            raise TypeError("a durable routing-decision recorder is required")
        if not callable(verify_registered_route):
            raise TypeError("a trusted route-registry verifier is required")
        self._record_decision = record_decision
        self._verify_registered_route = verify_registered_route
        self._routes: dict[str, ModelRoute] = {}

    def register(self, route: ModelRoute) -> None:
        if route.route_id in self._routes:
            raise ValueError("model route identifiers are immutable and unique")
        try:
            verified = self._verify_registered_route(route)
        except Exception as exc:
            raise RuntimeError("route registration could not be verified; failing closed") from exc
        if verified is not True:
            raise PermissionError("model route is not registered in the trusted Platform registry")
        self._routes[route.route_id] = route

    def route(self, request: ModelRoutingRequest) -> ModelRoutingDecision:
        candidates = [
            route
            for route in self._routes.values()
            if route.enabled
            and route.provider in request.provider_availability
            and request.task_policy in route.task_policies
            and request.model_capability in route.capabilities
            and request.risk_class in route.risk_classes
            and request.data_classification in route.data_classifications
            and request.risk_score <= route.max_risk_score
            and request.budget_microusd <= route.max_cost_microusd
            and (route.tenants is None or request.tenant_id in route.tenants)
            and (route.agents is None or request.agent_id in route.agents)
        ]
        candidates.sort(key=lambda item: (item.priority, item.route_id))
        selected = candidates[0] if candidates else None
        decision = ModelRoutingDecision(
            decision_id=str(uuid4()),
            allowed=selected is not None,
            route=selected.route_id if selected else None,
            provider=selected.provider if selected else None,
            model_id=selected.model if selected else None,
            task_policy=request.task_policy,
            policy_version=selected.policy_version if selected else None,
            reason_code="eligible_route_selected" if selected else "no_eligible_route",
            trace_id=request.trace_id,
        )
        try:
            self._record_decision(decision)
        except Exception as exc:
            raise RuntimeError("routing decision could not be recorded; failing closed") from exc
        return decision
