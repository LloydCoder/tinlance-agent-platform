import pytest

from tinlance_agent_platform_models import (
    ModelGateway,
    ModelRequest,
    ModelResponse,
    ModelRoute,
    ModelRouter,
    ModelRoutingRequest,
)


class Provider:
    def complete(self, request: ModelRequest) -> ModelResponse:
        return ModelResponse(request.model, "ok", 2, 1)


def test_model_gateway_preserves_tenant_and_usage_contract() -> None:
    gateway = ModelGateway()
    gateway.register("test", Provider())
    request = ModelRequest("t1", "a1", "model-x", ({"role": "user", "content": "hi"},))
    assert gateway.complete("test", request).output == "ok"


def test_model_request_rejects_invalid_messages() -> None:
    with pytest.raises(ValueError):
        ModelRequest("t1", "a1", "model-x", ({"role": "system"},))


def test_model_provider_allowlists_are_enforced() -> None:
    gateway = ModelGateway()
    gateway.register("restricted", Provider(), tenants=frozenset({"t1"}), agents=frozenset({"a1"}))
    allowed = ModelRequest("t1", "a1", "model-x", ({"role": "user", "content": "hi"},))
    denied = ModelRequest("t2", "a1", "model-x", ({"role": "user", "content": "hi"},))
    assert gateway.complete("restricted", allowed).output == "ok"
    with pytest.raises(PermissionError):
        gateway.complete("restricted", denied)


def test_model_response_cannot_exceed_requested_output_budget() -> None:
    class Oversized:
        def complete(self, request: ModelRequest) -> ModelResponse:
            return ModelResponse(request.model, "too much", 1, request.max_output_tokens + 1)

    gateway = ModelGateway()
    gateway.register("oversized", Oversized())
    request = ModelRequest(
        "t1",
        "a1",
        "model-x",
        ({"role": "user", "content": "hi"},),
        max_output_tokens=1,
    )
    with pytest.raises(ValueError):
        gateway.complete("oversized", request)


def trusted_router(recorder):
    return ModelRouter(recorder, lambda _route: True)


def routing_request(**overrides: object) -> ModelRoutingRequest:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "agent_id": "agent-a",
        "task_policy": "summarization-policy-v1",
        "model_capability": "summarization",
        "risk_class": "moderate",
        "data_classification": "confidential",
        "risk_score": 20,
        "budget_microusd": 50,
        "provider_availability": frozenset({"provider-a", "provider-b"}),
        "policy_version": "policy-7",
        "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
    }
    values.update(overrides)
    return ModelRoutingRequest(**values)  # type: ignore[arg-type]


def route(
    route_id: str,
    provider: str,
    *,
    priority: int = 100,
    tenants: frozenset[str] | None = None,
    classifications: frozenset[str] = frozenset({"public", "internal", "confidential"}),
    task_policies: frozenset[str] = frozenset({"summarization-policy-v1"}),
    risk_classes: frozenset[str] = frozenset({"low", "moderate"}),
    max_risk_score: int = 50,
    max_cost_microusd: int = 100,
    enabled: bool = True,
) -> ModelRoute:
    return ModelRoute(
        route_id=route_id,
        provider=provider,
        model=f"{provider}-model",
        capabilities=frozenset({"summarization"}),
        task_policies=task_policies,
        data_classifications=classifications,
        risk_classes=risk_classes,
        max_risk_score=max_risk_score,
        max_cost_microusd=max_cost_microusd,
        priority=priority,
        tenants=tenants,
        enabled=enabled,
    )


def test_model_router_selects_deterministic_lowest_priority_eligible_route() -> None:
    recorded = []
    router = trusted_router(recorded.append)
    router.register(route("route-b", "provider-b", priority=20))
    router.register(route("route-a", "provider-a", priority=10))

    decision = router.route(routing_request())

    assert decision.allowed
    assert decision.route_id == "route-a"
    assert decision.provider == "provider-a"
    assert decision.model == "provider-a-model"
    assert decision.policy_version == "policy-7"
    assert decision.task_policy == "summarization-policy-v1"
    assert decision.reason_code == "eligible_route_selected"
    assert decision.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert recorded == [decision]


def test_model_router_fails_closed_for_tenant_risk_data_budget_and_availability() -> None:
    recorded = []
    router = ModelRouter(recorded.append)
    router.register(
        route(
            "restricted-route",
            "provider-a",
            tenants=frozenset({"tenant-other"}),
            classifications=frozenset({"public"}),
            max_risk_score=5,
            max_cost_microusd=10,
        )
    )

    decision = router.route(routing_request())

    assert not decision.allowed
    assert decision.route_id is None
    assert decision.provider is None
    assert decision.reason_code == "no_eligible_route"
    assert recorded == [decision]


def test_model_router_does_not_select_unavailable_provider_or_disabled_route() -> None:
    recorded = []
    router = ModelRouter(recorded.append)
    router.register(route("disabled", "provider-a", enabled=False))
    router.register(route("offline", "provider-c", priority=1))

    decision = router.route(routing_request(provider_availability=frozenset({"provider-a"})))

    assert not decision.allowed
    assert decision.reason_code == "no_eligible_route"


def test_model_router_rejects_duplicate_route_ids() -> None:
    router = trusted_router(lambda _decision: None)
    router.register(route("same", "provider-a"))
    with pytest.raises(ValueError, match="immutable and unique"):
        router.register(route("same", "provider-b"))


def test_model_router_fails_closed_if_audit_recording_fails() -> None:
    def broken_recorder(_decision: object) -> None:
        raise OSError("audit backend unavailable")

    router = trusted_router(broken_recorder)
    router.register(route("route-a", "provider-a"))
    with pytest.raises(RuntimeError, match="failing closed"):
        router.route(routing_request())


@pytest.mark.parametrize(
    "kwargs",
    [
        {"risk_score": 101},
        {"risk_score": -1},
        {"budget_microusd": -1},
        {"data_classification": "top-secret"},
        {"provider_availability": frozenset()},
        {"trace_id": "0" * 32},
        {"trace_id": "invalid"},
    ],
)
def test_model_routing_request_rejects_invalid_risk_budget_and_context(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        routing_request(**kwargs)



def test_model_router_rejects_unregistered_route_and_registry_outage() -> None:
    denied = ModelRouter(lambda _decision: None, lambda _route: False)
    with pytest.raises(PermissionError, match="not registered"):
        denied.register(route("unregistered", "provider-a"))

    def registry_outage(_route: ModelRoute) -> bool:
        raise OSError("registry unavailable")

    unavailable = ModelRouter(lambda _decision: None, registry_outage)
    with pytest.raises(RuntimeError, match="failing closed"):
        unavailable.register(route("unverified", "provider-a"))
