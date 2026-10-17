from uuid import uuid4

import pytest

from tinlance_agent_platform_agents import AgentRegistry
from tinlance_agent_platform_approvals import ApprovalService
from tinlance_agent_platform_contracts import (
    AgentDefinition,
    CapabilityRequest,
    DataClass,
    Principal,
    RequestContext,
    Reversibility,
    RiskTier,
    ToolCall,
)
from tinlance_agent_platform_events import InMemoryEventStore
from tinlance_agent_platform_evidence import InMemoryEvidenceStore
from tinlance_agent_platform_execution import (
    ExecutionErrorCode,
    ExecutionFailure,
    ExecutionRequest,
    GovernedExecutionService,
)
from tinlance_agent_platform_tools import ToolGateway, ToolRegistration


class Reader:
    def execute(self, call: ToolCall) -> str:
        return f"ok:{call.resource}"


def request() -> CapabilityRequest:
    return CapabilityRequest(
        "read",
        "doc:1",
        frozenset({"doc:read"}),
        RiskTier.LOW,
        Reversibility.REVERSIBLE,
        DataClass.INTERNAL,
        "single",
    )


def test_tool_gateway_requires_platform_issued_single_use_permit() -> None:
    gateway = ToolGateway()
    gateway.register(ToolRegistration("reader", "doc:read", "reader"), Reader())
    principal = Principal("user", "human", "tenant-a", scopes=frozenset({"doc:read"}))
    context = RequestContext("req", "tenant-a", principal, "test")
    call = ToolCall(uuid4(), "tenant-a", uuid4(), "reader", "doc:read", "read", "doc:1")
    decision = gateway.authorize(context, call, request())
    permit = gateway.issue_permit(call, decision)
    assert gateway.execute(call, permit) == "ok:doc:1"
    with pytest.raises(PermissionError):
        gateway.execute(call, permit)


def test_tool_gateway_rejects_permit_for_different_call() -> None:
    gateway = ToolGateway()
    gateway.register(ToolRegistration("reader", "doc:read", "reader"), Reader())
    principal = Principal("user", "human", "tenant-a", scopes=frozenset({"doc:read"}))
    context = RequestContext("req", "tenant-a", principal, "test")
    call = ToolCall(uuid4(), "tenant-a", uuid4(), "reader", "doc:read", "read", "doc:1")
    decision = gateway.authorize(context, call, request())
    permit = gateway.issue_permit(call, decision)
    different = ToolCall(uuid4(), "tenant-a", call.run_id, "reader", "doc:read", "read", "doc:2")
    with pytest.raises(PermissionError):
        gateway.execute(different, permit)


class CountingReader:
    def __init__(self) -> None:
        self.calls = 0

    def execute(self, call: ToolCall) -> str:
        self.calls += 1
        return f"executed:{call.resource}"


def _critical_execution(risk: RiskTier):
    tenant = "tenant-risk-floor"
    subject = "principal-risk-floor"
    agent_id = uuid4()
    run_id = uuid4()
    agents = AgentRegistry()
    agents.register(
        AgentDefinition(
            agent_id,
            tenant,
            "critical-deployment",
            "1.0.0",
            subject,
            "default",
            frozenset({"deployment.trigger"}),
            "a" * 64,
        )
    )
    executor = CountingReader()
    tools = ToolGateway()
    tools.register(
        ToolRegistration(
            "deployment.trigger",
            "deployment.trigger",
            "Critical deployment operation",
            version="1",
            risk=RiskTier.CRITICAL,
            timeout_seconds=30.0,
            max_tool_calls=1,
        ),
        executor,
    )
    service = GovernedExecutionService(
        agents=agents,
        approvals=ApprovalService(),
        tools=tools,
        events=InMemoryEventStore(),
        evidence=InMemoryEvidenceStore(),
    )
    principal = Principal(
        subject,
        "human",
        tenant,
        scopes=frozenset({"deployment.trigger"}),
    )
    request_value = ExecutionRequest(
        request_id="risk-floor-request-0001",
        idempotency_key="risk-floor-idempotency-0001",
        tenant_id=tenant,
        principal_id=subject,
        agent_id=agent_id,
        run_id=run_id,
        capability_id="deployment.trigger",
        capability_version="1",
        tool_name="deployment.trigger",
        tool_version="1",
        action="deploy",
        resource="environment:production",
        input={},
        requested_timeout_seconds=30.0,
        risk=risk,
        reversibility=Reversibility.IRREVERSIBLE,
        data_class=DataClass.SENSITIVE,
        blast_radius="production",
        evidence_required=True,
    )
    return service, principal, request_value, executor


def test_registered_tool_risk_cannot_be_downgraded_by_caller() -> None:
    service, principal, request_value, executor = _critical_execution(RiskTier.LOW)
    with pytest.raises(ExecutionFailure) as failure:
        service.execute(principal, request_value)
    assert failure.value.code is ExecutionErrorCode.AUTHORIZATION_DENIED
    assert executor.calls == 0


def test_registered_critical_tool_requires_approval_before_any_side_effect() -> None:
    service, principal, request_value, executor = _critical_execution(RiskTier.CRITICAL)
    with pytest.raises(ExecutionFailure) as failure:
        service.execute(principal, request_value)
    assert failure.value.code is ExecutionErrorCode.APPROVAL_REQUIRED
    assert failure.value.execution_id is not None
    assert executor.calls == 0
