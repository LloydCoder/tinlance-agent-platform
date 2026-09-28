import pytest

from tinlance_agent_platform_models import ModelGateway, ModelRequest, ModelResponse


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
