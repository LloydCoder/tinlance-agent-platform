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
