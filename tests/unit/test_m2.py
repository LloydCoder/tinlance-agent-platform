from uuid import uuid4

import pytest

from tinlance_agent_platform_contracts import Run, TaskSpec
from tinlance_agent_platform_events import InMemoryEventStore, new_event
from tinlance_agent_platform_evidence import InMemoryEvidenceStore
from tinlance_agent_platform_models import ModelGateway, ModelRequest, ModelResponse
from tinlance_agent_platform_orchestration import AgentRunner


class FakeProvider:
    def complete(self, request: ModelRequest) -> ModelResponse:
        return ModelResponse(request.model, "ok", 2, 1)


def test_model_gateway_is_provider_neutral() -> None:
    gateway = ModelGateway()
    gateway.register("fake", FakeProvider())
    request = ModelRequest(
        "t1",
        "a1",
        "model",
        ({"role": "user", "content": "hi"},),
    )
    result = gateway.complete("fake", request)
    assert result.output == "ok"


def test_model_gateway_rejects_unknown_provider() -> None:
    request = ModelRequest("t1", "a1", "m", ())
    with pytest.raises(LookupError):
        ModelGateway().complete("missing", request)


def test_runner_binds_run_to_task() -> None:
    run = Run(uuid4(), uuid4(), "t1")
    task = TaskSpec(uuid4(), "t1", uuid4(), "1", "u", "do")
    with pytest.raises(PermissionError):
        AgentRunner(lambda _t, _n: "ok").start(run, task)


def test_event_and_evidence_are_tenant_scoped() -> None:
    run_id = uuid4()
    events = InMemoryEventStore()
    events.append(new_event("t1", run_id, "run.started", {"status": "running"}))
    assert len(events.list_for_run("t1", run_id)) == 1
    assert not events.list_for_run("t2", run_id)
    evidence = InMemoryEvidenceStore().append("t1", run_id, "artifact")
    assert len(evidence.content_hash) == 64
