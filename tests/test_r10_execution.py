from __future__ import annotations

from uuid import uuid4

import pytest

from tinlance_agent_platform_agents import AgentRegistry
from tinlance_agent_platform_approvals import ApprovalService
from tinlance_agent_platform_contracts import (
    AgentDefinition,
    DataClass,
    Principal,
    Reversibility,
    RiskTier,
)
from tinlance_agent_platform_events import InMemoryEventStore
from tinlance_agent_platform_evidence import InMemoryEvidenceStore
from tinlance_agent_platform_execution import (
    ExecutionErrorCode,
    ExecutionFailure,
    ExecutionRequest,
    ExecutionState,
    GovernedExecutionService,
)
from tinlance_agent_platform_tools import ToolCall, ToolGateway, ToolRegistration


class Echo:
    def execute(self, call: ToolCall) -> str:
        return f"executed:{call.action}:{call.resource}"


@pytest.fixture
def harness() -> tuple[GovernedExecutionService, Principal, AgentDefinition, object]:
    tenant = "tenant-r10"
    principal = Principal("user-r10", "user", tenant, scopes=frozenset({"repository.read"}))
    agent = AgentDefinition(
        uuid4(), tenant, "r10-agent", "1.0.0", principal.subject_id,
        "default", frozenset({"repository.read"}), "sha256:instructions",
    )
    agents = AgentRegistry()
    agents.register(agent)
    tools = ToolGateway()
    tools.register(
        ToolRegistration(
            "reference.echo", "repository.read", "reference tool", version="1",
            risk=RiskTier.HIGH, timeout_seconds=10, max_tool_calls=1,
        ),
        Echo(),
    )
    service = GovernedExecutionService(
        agents=agents,
        approvals=ApprovalService(),
        tools=tools,
        events=InMemoryEventStore(),
        evidence=InMemoryEvidenceStore(),
    )
    return service, principal, agent, tools


def request(principal: Principal, agent: AgentDefinition, **overrides: object) -> ExecutionRequest:
    values: dict[str, object] = {
        "request_id": str(uuid4()),
        "idempotency_key": str(uuid4()),
        "tenant_id": principal.tenant_id,
        "principal_id": principal.subject_id,
        "agent_id": agent.agent_id,
        "run_id": uuid4(),
        "capability_id": "repository.read",
        "capability_version": "1",
        "tool_name": "reference.echo",
        "tool_version": "1",
        "action": "read",
        "resource": "repo:example",
        "input": {"safe": True},
        "requested_timeout_seconds": 5,
    }
    values.update(overrides)
    return ExecutionRequest(**values)  # type: ignore[arg-type]


def test_golden_path_binds_identity_evidence_and_audit(harness: object) -> None:
    service, principal, agent, _ = harness
    item = service.execute(principal, request(principal, agent))
    assert item.state is ExecutionState.COMPLETED
    assert item.output == "executed:read:repo:example"
    assert len(item.evidence_ids) == 1
    assert len(item.audit_event_ids) >= 5


def test_cross_tenant_identity_is_denied(harness: object) -> None:
    service, principal, agent, _ = harness
    foreign = Principal(principal.subject_id, "user", "tenant-other")
    with pytest.raises(ExecutionFailure) as exc:
        service.execute(foreign, request(principal, agent))
    assert exc.value.code is ExecutionErrorCode.IDENTITY_BINDING_FAILED


def test_idempotency_returns_same_result_and_conflicting_key_fails(harness: object) -> None:
    service, principal, agent, _ = harness
    key = str(uuid4())
    first = request(principal, agent, idempotency_key=key)
    result = service.execute(principal, first)
    assert service.execute(principal, first) == result
    conflicting = request(principal, agent, idempotency_key=key, resource="repo:other")
    with pytest.raises(ExecutionFailure) as exc:
        service.execute(principal, conflicting)
    assert exc.value.code is ExecutionErrorCode.IDEMPOTENCY_CONFLICT


def test_high_risk_requires_approval_and_cannot_self_approve(harness: object) -> None:
    service, principal, agent, _ = harness
    high = request(principal, agent, risk=RiskTier.HIGH)
    with pytest.raises(ExecutionFailure) as exc:
        service.execute(principal, high)
    assert exc.value.code is ExecutionErrorCode.APPROVAL_REQUIRED
    approval = service.approvals.request(
        principal.tenant_id, high.run_id, high.action, high.resource, "high-risk", principal.subject_id
    )
    with pytest.raises(PermissionError):
        service.approvals.decide(approval.approval_id, True, principal.tenant_id, principal.subject_id)
    service.approvals.decide(approval.approval_id, True, principal.tenant_id, "approver")
    completed = service.execute(principal, high, trace_id="trace-r10")
    assert completed.state is ExecutionState.COMPLETED
    replay = request(
        principal, agent, risk=RiskTier.HIGH, approval_id=approval.approval_id
    )
    with pytest.raises(ExecutionFailure) as replay_error:
        service.execute(principal, replay)
    assert replay_error.value.code is ExecutionErrorCode.EXECUTION_OUTCOME_UNKNOWN


def test_unknown_prior_idempotent_execution_never_replays(harness: object) -> None:
    service, principal, agent, _ = harness
    key = str(uuid4())
    record = request(principal, agent, idempotency_key=key)
    from tinlance_agent_platform_execution import IdempotencyRecord
    service.idempotency.claim(IdempotencyRecord(principal.tenant_id, key, record.fingerprint, uuid4()))
    with pytest.raises(ExecutionFailure) as exc:
        service.execute(principal, record)
    assert exc.value.code is ExecutionErrorCode.EXECUTION_OUTCOME_UNKNOWN


def test_required_sandbox_fails_closed(harness: object) -> None:
    service, principal, agent, _ = harness
    with pytest.raises(ExecutionFailure) as exc:
        service.execute(principal, request(principal, agent, sandbox_required=True))
    assert exc.value.code is ExecutionErrorCode.SANDBOX_UNAVAILABLE


def test_budget_limit_is_enforced(harness: object) -> None:
    service, principal, agent, _ = harness
    with pytest.raises(ExecutionFailure) as exc:
        service.execute(principal, request(principal, agent, requested_tool_calls=2))
    assert exc.value.code is ExecutionErrorCode.BUDGET_EXCEEDED
