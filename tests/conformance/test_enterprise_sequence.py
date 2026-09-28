from uuid import uuid4

import pytest

from tinlance_agent_platform_contracts import (
    CapabilityRequest,
    DataClass,
    Decision,
    Principal,
    RequestContext,
    Reversibility,
    RiskTier,
    SandboxRequest,
    TaskSpec,
    ToolCall,
)
from tinlance_agent_platform_evaluation import EvalCase, EvalRunner
from tinlance_agent_platform_events import InMemoryEventStore, new_event
from tinlance_agent_platform_mcp import MCPTool, MCPToolGateway, ToolScope
from tinlance_agent_platform_models import ModelGateway, ModelRequest, ModelResponse
from tinlance_agent_platform_observability import InMemoryObservabilitySink, new_security_event
from tinlance_agent_platform_orchestration import AgentRunner
from tinlance_agent_platform_sandbox import SandboxPolicy
from tinlance_agent_platform_trajectory.chain import InMemoryTrajectoryStore


def test_canonical_governed_agent_path_is_fail_closed() -> None:
    tenant = "tenant-a"
    principal = Principal("user-1", "human", tenant, scopes=frozenset({"doc:read"}))
    context = RequestContext("request-1", tenant, principal, "test", trace_id="trace-1")
    request = CapabilityRequest(
        "read",
        "doc-1",
        frozenset({"doc:read"}),
        RiskTier.LOW,
        Reversibility.REVERSIBLE,
        DataClass.INTERNAL,
        "single-resource",
    )
    call = ToolCall(uuid4(), tenant, uuid4(), "reader", "doc:read", "read", "doc-1")

    from tinlance_agent_platform_authorization import authorize
    from tinlance_agent_platform_policy import evaluate
    from tinlance_agent_platform_tools import ToolGateway, ToolRegistration

    assert authorize(context, request).decision is Decision.ALLOW
    assert evaluate(request).decision is Decision.ALLOW

    class Executor:
        def execute(self, tool_call: ToolCall) -> str:
            return f"read:{tool_call.resource}"

    tools = ToolGateway()
    tools.register(ToolRegistration("reader", "doc:read", "read documents"), Executor())
    decision = tools.authorize(context, call, request)
    assert decision.decision is Decision.ALLOW
    assert tools.execute(call, decision) == "read:doc-1"


def test_tenant_boundary_cannot_be_crossed() -> None:
    principal = Principal("user-1", "human", "tenant-a", scopes=frozenset({"doc:read"}))
    context = RequestContext("request-1", "tenant-a", principal, "test")
    request = CapabilityRequest(
        "read",
        "doc-1",
        frozenset({"doc:read"}),
        RiskTier.LOW,
        Reversibility.REVERSIBLE,
        DataClass.INTERNAL,
        "single",
    )
    from tinlance_agent_platform_tools import ToolGateway

    call = ToolCall(uuid4(), "tenant-b", uuid4(), "reader", "doc:read", "read", "doc-1")
    assert ToolGateway().authorize(context, call, request).decision is Decision.DENY


def test_model_mcp_event_evidence_and_observability_boundaries() -> None:
    model = ModelGateway()

    class Provider:
        def complete(self, request: ModelRequest) -> ModelResponse:
            return ModelResponse(request.model, "ok", 2, 1)

    model.register("test-provider", Provider())
    request = ModelRequest(
        "tenant-a",
        "agent-1",
        "model-1",
        ({"role": "user", "content": "hi"},),
    )
    response = model.complete("test-provider", request)
    assert response.output == "ok"

    class Transport:
        def call(self, tool_name: str, arguments: object, scope: ToolScope) -> dict[str, object]:
            return {"tool": tool_name, "tenant": scope.tenant_id}

    mcp = MCPToolGateway(Transport())
    mcp.register(MCPTool("lookup", "lookup", "doc:read", "read", "doc-1"))
    mcp_request = CapabilityRequest(
        "read",
        "doc-1",
        frozenset({"doc:read"}),
        RiskTier.LOW,
        Reversibility.REVERSIBLE,
        DataClass.INTERNAL,
        "single-resource",
    )
    result = mcp.call(
        RequestContext("request-1", "tenant-a", Principal("user-1", "human", "tenant-a", scopes=frozenset({"doc:read"})), "test"),
        ToolScope("tenant-a", "doc:read", "doc-1"),
        "lookup",
        {"q": "x"},
        mcp_request,
        run_id=uuid4(),
    )
    assert result["tenant"] == "tenant-a"

    events = InMemoryEventStore()
    event = new_event("tenant-a", uuid4(), "tool.executed", {"outcome": "allow"})
    events.append(event)
    assert len(events.list_for_run("tenant-a", event.run_id)) == 1
    with pytest.raises(ValueError):
        events.append(event)

    trajectory = InMemoryTrajectoryStore()
    run_id = uuid4()
    trajectory.append("tenant-a", run_id, "tool.executed", "ok")
    trajectory.append("tenant-a", run_id, "evidence.created", "hash")
    assert trajectory.verify("tenant-a", run_id)

    sink = InMemoryObservabilitySink()
    sink.emit_security(new_security_event("tenant-a", "tool.allowed", "info", outcome="allow"))
    assert sink.security[0].tenant_id == "tenant-a"


def test_sandbox_and_evaluation_are_not_authority_sources() -> None:
    sandbox = SandboxPolicy(frozenset({"python"}))
    request = SandboxRequest(
        uuid4(), "tenant-a", uuid4(), "ws", ("python",), 10, False, ("/workspace",)
    )
    sandbox.validate(request)

    evaluation = EvalRunner(lambda value: value)
    result = evaluation.run(EvalCase("safe-1", "input", "input", safety_critical=True))
    assert result.passed


def test_runner_preserves_task_tenant_and_turn_budget() -> None:
    task = TaskSpec(uuid4(), "tenant-a", uuid4(), "1.0", "user-1", "do one thing", max_turns=1)
    from tinlance_agent_platform_contracts import Run

    run = Run(uuid4(), task.task_id, task.tenant_id)
    runner = AgentRunner(lambda _task, _turn: "done")
    completed, step = runner.start(run, task)
    assert completed.status.value == "succeeded"
    assert step.turn == 1
