from uuid import uuid4

from tinlance_agent_platform_approvals import ApprovalService
from tinlance_agent_platform_authorization import authorize
from tinlance_agent_platform_contracts import (
    AgentDefinition,
    CapabilityRequest,
    DataClass,
    Decision,
    Principal,
    RequestContext,
    Reversibility,
    RiskTier,
    Run,
    TaskSpec,
    ToolCall,
)
from tinlance_agent_platform_events import InMemoryEventStore, new_event
from tinlance_agent_platform_observability import (
    InMemoryObservabilitySink,
    new_security_event,
)
from tinlance_agent_platform_orchestration import AgentRunner
from tinlance_agent_platform_policy import evaluate
from tinlance_agent_platform_tools import ToolGateway, ToolRegistration


def test_hello_governed_agent_executes_only_after_complete_mediation() -> None:
    tenant_id = "tenant-a"
    agent_id = uuid4()
    task_id = uuid4()
    run_id = uuid4()

    principal = Principal(
        subject_id="user-1",
        principal_type="human",
        tenant_id=tenant_id,
        scopes=frozenset({"document:write"}),
    )
    context = RequestContext(
        request_id="request-1",
        tenant_id=tenant_id,
        principal=principal,
        environment="test",
        trace_id="trace-1",
    )
    definition = AgentDefinition(
        agent_id=agent_id,
        tenant_id=tenant_id,
        name="governed-demo",
        version="1.0",
        owner_subject_id="user-1",
        policy_profile="default",
        capabilities=frozenset({"document:write"}),
        instructions_hash="sha256:demo",
    )
    task = TaskSpec(
        task_id=task_id,
        tenant_id=tenant_id,
        agent_id=definition.agent_id,
        agent_version=definition.version,
        requester_subject_id="user-1",
        objective="perform a supervised document write",
        max_turns=2,
    )
    run = Run(run_id=run_id, task_id=task_id, tenant_id=tenant_id)

    runner = AgentRunner(lambda current_task, turn: f"proposed:{current_task.objective}:{turn}")
    running, step = runner.start(run, task)
    assert running.status.value == "succeeded"
    assert step.output.startswith("proposed:")

    request = CapabilityRequest(
        action="write",
        resource="document:123",
        capabilities=frozenset({"document:write"}),
        risk=RiskTier.HIGH,
        reversibility=Reversibility.REVERSIBLE,
        data_class=DataClass.INTERNAL,
        blast_radius="single-resource",
    )
    authorization = authorize(context, request)
    assert authorization.decision is Decision.ALLOW

    policy = evaluate(request)
    assert policy.decision is Decision.REQUIRE_APPROVAL
    assert policy.requires_approval is True

    approvals = ApprovalService()
    approval = approvals.request(
        tenant_id,
        run_id,
        request.action,
        request.resource,
        "high-risk write requires human review",
        "user-1",
    )
    approvals.decide(approval.approval_id, True, tenant_id)

    executed: list[ToolCall] = []

    class Executor:
        def execute(self, call: ToolCall) -> str:
            executed.append(call)
            return "ok"

    gateway = ToolGateway()
    gateway.register(
        ToolRegistration("document-writer", "document:write", "write a document"),
        Executor(),
    )
    call = ToolCall(
        call_id=uuid4(),
        tenant_id=tenant_id,
        run_id=run_id,
        tool_name="document-writer",
        capability="document:write",
        action="write",
        resource="document:123",
    )
    decision = gateway.authorize(context, call, request)
    assert decision.decision is Decision.REQUIRE_APPROVAL
    assert gateway.execute(call, decision, approval.approval_id, approvals) == "ok"
    assert executed == [call]

    events = InMemoryEventStore()
    event = events.append(
        new_event(
            tenant_id,
            run_id,
            "tool.executed",
            {"tool": call.tool_name, "decision": decision.decision.value},
        )
    )
    assert events.list_for_run(tenant_id, run_id) == (event,)

    telemetry = InMemoryObservabilitySink()
    telemetry.emit_security(
        new_security_event(
            tenant_id,
            "tool.executed",
            "info",
            actor_id="user-1",
            trace_id="trace-1",
            outcome="allow",
        )
    )
    assert telemetry.security[0].tenant_id == tenant_id
