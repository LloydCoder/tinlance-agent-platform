from uuid import uuid4

import pytest

from tinlance_agent_platform_approvals import ApprovalService
from tinlance_agent_platform_authorization import authorize
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
from tinlance_agent_platform_mcp import MCPTool, MCPToolGateway
from tinlance_agent_platform_models import ModelGateway, ModelRequest, ModelResponse
from tinlance_agent_platform_observability import InMemoryObservabilitySink
from tinlance_agent_platform_orchestration import GovernedRunService
from tinlance_agent_platform_tools import ToolGateway, ToolRegistration
from tinlance_agent_platform_trajectory import InMemoryTrajectoryStore


def test_governed_run_stops_before_high_risk_side_effect() -> None:
    tenant = "tenant-a"
    run_id = uuid4()
    agent_id = uuid4()
    task = TaskSpec(uuid4(), tenant, agent_id, "1", "human", "delete one record")
    run = Run(run_id, task.task_id, tenant)
    context = RequestContext(
        "req", tenant, Principal("human", "human", tenant, scopes=frozenset({"db:delete"})), "test"
    )
    tool_call = ToolCall(uuid4(), tenant, run_id, "delete", "db:delete", "delete", "db:item")

    class Provider:
        def complete(self, request: ModelRequest) -> ModelResponse:
            return ModelResponse(request.model, "review required", tool_calls=(tool_call,))

    class Executor:
        def execute(self, call: ToolCall) -> str:
            pytest.fail("high-risk side effect executed before approval")

    models = ModelGateway()
    models.register("test", Provider())
    tools = ToolGateway()
    tools.register(ToolRegistration("delete", "db:delete", "delete"), Executor())
    approvals = ApprovalService()
    budget = BudgetService(Budget(uuid4(), tenant, run_id, 5, 60, 5))
    events = InMemoryEventStore()
    trajectory = InMemoryTrajectoryStore()
    telemetry = InMemoryObservabilitySink()
    service = GovernedRunService(
        models, tools, approvals, budget, events, trajectory, telemetry, "test"
    )
    result = service.run(
        context,
        run,
        task,
        "model",
        (("user", "delete"),),
        lambda call: CapabilityRequest(
            call.action,
            call.resource,
            frozenset({call.capability}),
            RiskTier.HIGH,
            Reversibility.IRREVERSIBLE,
            DataClass.INTERNAL,
            "single-resource",
        ),
    )
    assert result.run.status.value == "waiting_approval"
    assert result.approval_id is not None
    assert events.list_for_run(tenant, run_id)
    assert trajectory.verify(tenant, run_id)


def test_model_gateway_rejects_cross_tenant_tool_result() -> None:
    class Provider:
        def complete(self, request: ModelRequest) -> ModelResponse:
            return ModelResponse(
                "model",
                "bad",
                tool_calls=(ToolCall(uuid4(), "tenant-b", uuid4(), "x", "x", "x", "x"),),
            )

    gateway = ModelGateway()
    gateway.register("test", Provider())
    with pytest.raises(PermissionError):
        gateway.complete("test", ModelRequest("tenant-a", "agent", "model", (("user", "hi"),)))


def test_mcp_requires_governed_path_for_approval_tools() -> None:
    class Transport:
        def call(self, tool_name: str, arguments: dict[str, object]) -> dict[str, object]:
            return {"tool": tool_name}

    gateway = MCPToolGateway(Transport())
    gateway.register(MCPTool("delete", "delete", "db:delete", "db:*", requires_approval=True))
    with pytest.raises(PermissionError):
        gateway.call(
            type("Scope", (), {"tenant_id": "t1", "capability": "db:delete", "resource": "db:x"})(),
            "delete",
            {},
        )


def test_mcp_governed_path_uses_platform_authorization() -> None:
    class Transport:
        def call(self, tool_name: str, arguments: dict[str, object]) -> dict[str, object]:
            return {"tool": tool_name}

    gateway = MCPToolGateway(Transport())
    gateway.register(MCPTool("read", "read", "repo:read", "repo:*"))
    context = RequestContext(
        "r", "t1", Principal("u", "human", "t1", scopes=frozenset({"repo:read"})), "test"
    )
    call = ToolCall(uuid4(), "t1", uuid4(), "read", "repo:read", "read", "repo:x")
    request = CapabilityRequest(
        "read",
        "repo:x",
        frozenset({"repo:read"}),
        RiskTier.LOW,
        Reversibility.REVERSIBLE,
        DataClass.INTERNAL,
        "single",
    )
    result = gateway.governed_call(
        context, call, request, type("A", (), {"authorize": staticmethod(authorize)})()
    )
    assert result["tool"] == "read"
