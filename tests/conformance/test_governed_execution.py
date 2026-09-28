from uuid import uuid4

from tinlance_agent_platform_contracts import (
    CapabilityRequest,
    DataClass,
    Principal,
    RequestContext,
    Reversibility,
    RiskTier,
    Run,
    TaskSpec,
    ToolCall,
)
from tinlance_agent_platform_evidence import InMemoryEvidenceStore
from tinlance_agent_platform_events import InMemoryEventStore
from tinlance_agent_platform_models import ModelGateway, ModelRequest, ModelResponse
from tinlance_agent_platform_observability import InMemoryObservabilitySink
from tinlance_agent_platform_orchestration import GovernedExecutionService
from tinlance_agent_platform_tools import ToolGateway, ToolRegistration
from tinlance_agent_platform_trajectory.chain import InMemoryTrajectoryStore


class Provider:
    def complete(self, request: ModelRequest) -> ModelResponse:
        return ModelResponse(request.model, "plan", 1, 1)


class Reader:
    def execute(self, call: ToolCall) -> str:
        return f"evidence:{call.resource}"


def test_full_governed_execution_path() -> None:
    tenant = "tenant-a"
    agent_id = uuid4()
    task_id = uuid4()
    run_id = uuid4()
    principal = Principal("user-1", "human", tenant, scopes=frozenset({"doc:read"}))
    context = RequestContext("req-1", tenant, principal, "test", trace_id="trace-1")
    task = TaskSpec(task_id, tenant, agent_id, "1.0", "user-1", "read one document", max_turns=1)
    run = Run(run_id, task_id, tenant)
    capability = CapabilityRequest(
        "read",
        "doc-1",
        frozenset({"doc:read"}),
        RiskTier.LOW,
        Reversibility.REVERSIBLE,
        DataClass.INTERNAL,
        "single-resource",
    )
    call = ToolCall(uuid4(), tenant, run_id, "reader", "doc:read", "read", "doc-1")

    models = ModelGateway()
    models.register(
        "provider",
        Provider(),
        tenants=frozenset({tenant}),
        agents=frozenset({str(agent_id)}),
    )
    tools = ToolGateway()
    tools.register(ToolRegistration("reader", "doc:read", "read documents"), Reader())

    events = InMemoryEventStore()
    evidence = InMemoryEvidenceStore()
    trajectory = InMemoryTrajectoryStore()
    observability = InMemoryObservabilitySink()
    service = GovernedExecutionService(
        models, tools, events, evidence, trajectory, observability
    )

    result = service.execute(
        context,
        task,
        run,
        "provider",
        ModelRequest(tenant, str(agent_id), "model-1", ({"role": "user", "content": "read"},)),
        capability,
        call,
    )

    assert result.model_response.output == "plan"
    assert result.tool_output == "evidence:doc-1"
    assert evidence.verify(tenant, run_id)
    assert trajectory.verify(tenant, run_id)
    assert len(events.list_for_run(tenant, run_id)) == 2
    assert observability.security[-1].outcome == "allow"


def test_full_governed_execution_rejects_cross_tenant_before_model() -> None:
    tenant = "tenant-a"
    principal = Principal("user-1", "human", tenant, scopes=frozenset({"doc:read"}))
    context = RequestContext("req-1", tenant, principal, "test")
    task = TaskSpec(uuid4(), tenant, uuid4(), "1.0", "user-1", "read")
    run = Run(uuid4(), task.task_id, tenant)
    models = ModelGateway()
    models.register("provider", Provider(), tenants=frozenset({tenant}))
    service = GovernedExecutionService(
        models,
        ToolGateway(),
        InMemoryEventStore(),
        InMemoryEvidenceStore(),
        InMemoryTrajectoryStore(),
        InMemoryObservabilitySink(),
    )
    capability = CapabilityRequest(
        "read",
        "doc-1",
        frozenset({"doc:read"}),
        RiskTier.LOW,
        Reversibility.REVERSIBLE,
        DataClass.INTERNAL,
        "single-resource",
    )
    call = ToolCall(uuid4(), "tenant-b", run.run_id, "reader", "doc:read", "read", "doc-1")
    request = ModelRequest(
        tenant,
        str(task.agent_id),
        "model-1",
        ({"role": "user", "content": "x"},),
    )

    try:
        service.execute(context, task, run, "provider", request, capability, call)
    except PermissionError:
        return
    raise AssertionError("cross-tenant execution must fail closed")
