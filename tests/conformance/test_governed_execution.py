from uuid import UUID, uuid4

import pytest

from tinlance_agent_platform_approvals import ApprovalService
from tinlance_agent_platform_budgets import BudgetService
from tinlance_agent_platform_contracts import (
    Budget,
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
from tinlance_agent_platform_events import InMemoryEventStore
from tinlance_agent_platform_evidence import InMemoryEvidenceStore
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


def build_service(
    tenant: str, run_id: UUID, models: ModelGateway, tools: ToolGateway
) -> GovernedExecutionService:
    budget = BudgetService(Budget(uuid4(), tenant, run_id, 2, 30.0, 1))
    return GovernedExecutionService(
        models,
        tools,
        budget,
        InMemoryEventStore(),
        InMemoryEvidenceStore(),
        InMemoryTrajectoryStore(),
        InMemoryObservabilitySink(),
    )


def test_full_governed_execution_path() -> None:
    tenant = "tenant-a"
    agent_id = uuid4()
    task_id = uuid4()
    run_id = uuid4()
    principal = Principal("user-1", "human", tenant, scopes=frozenset({"doc:read"}))
    context = RequestContext("req-1", tenant, principal, "test", trace_id="trace-1")
    task = TaskSpec(task_id, tenant, agent_id, "1.0", "user-1", "read", max_turns=1)
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
    service = build_service(tenant, run_id, models, tools)

    result = service.execute(
        context,
        task,
        run,
        "provider",
        ModelRequest(tenant, str(agent_id), "model-1", ({"role": "user", "content": "read"},)),
        capability,
        call,
    )

    assert result.run.status.value == "succeeded"
    assert result.model_response.output == "plan"
    assert result.tool_output == "evidence:doc-1"


def test_cross_tenant_request_fails_before_model() -> None:
    tenant = "tenant-a"
    principal = Principal("user-1", "human", tenant, scopes=frozenset({"doc:read"}))
    context = RequestContext("req-1", tenant, principal, "test")
    task = TaskSpec(uuid4(), tenant, uuid4(), "1.0", "user-1", "read")
    run = Run(uuid4(), task.task_id, tenant)
    models = ModelGateway()
    models.register("provider", Provider(), tenants=frozenset({tenant}))
    service = build_service(tenant, run.run_id, models, ToolGateway())
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

    with pytest.raises(PermissionError):
        service.execute(context, task, run, "provider", request, capability, call)


def test_high_risk_path_requires_exact_human_approval() -> None:
    tenant = "tenant-a"
    agent_id = uuid4()
    task = TaskSpec(uuid4(), tenant, agent_id, "1.0", "user-1", "write", max_turns=2)
    run = Run(uuid4(), task.task_id, tenant)
    principal = Principal("user-1", "human", tenant, scopes=frozenset({"doc:write"}))
    context = RequestContext("req-approval", tenant, principal, "test")
    capability = CapabilityRequest(
        "write",
        "doc-1",
        frozenset({"doc:write"}),
        RiskTier.HIGH,
        Reversibility.IRREVERSIBLE,
        DataClass.SENSITIVE,
        "single-resource",
    )
    call = ToolCall(uuid4(), tenant, run.run_id, "writer", "doc:write", "write", "doc-1")
    models = ModelGateway()
    models.register("provider", Provider(), tenants=frozenset({tenant}))
    tools = ToolGateway()

    class Writer:
        def execute(self, tool_call: ToolCall) -> str:
            return f"written:{tool_call.resource}"

    tools.register(ToolRegistration("writer", "doc:write", "write documents"), Writer())
    approvals = ApprovalService()
    approval = approvals.request(tenant, run.run_id, "write", "doc-1", "required", "user-1")
    service = build_service(tenant, run.run_id, models, tools)
    model_request = ModelRequest(
        tenant,
        str(agent_id),
        "model-1",
        ({"role": "user", "content": "write"},),
    )

    with pytest.raises(PermissionError):
        service.execute(context, task, run, "provider", model_request, capability, call)

    approvals.decide(approval.approval_id, True, tenant)
    result = service.execute(
        context,
        task,
        run,
        "provider",
        model_request,
        capability,
        call,
        approval_id=approval.approval_id,
        approval_verifier=approvals,
    )
    assert result.tool_output == "written:doc-1"
