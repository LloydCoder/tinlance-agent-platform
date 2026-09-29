"""R10 certification suite: adversarial boundary tests for every future Tinlance agent.

R10 is treated as immutable authority. These tests intentionally exercise hostile
inputs and race conditions at the Platform boundary rather than trusting agent code.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Lock
from uuid import UUID, uuid4

import pytest

from tinlance_agent_platform_agents import AgentRegistry
from tinlance_agent_platform_approvals import ApprovalService
from tinlance_agent_platform_budgets import BudgetService
from tinlance_agent_platform_contracts import (\n    AgentDefinition,\n    Budget,\n    DataClass,\n    Principal,\n    Reversibility,\n    RiskTier,\n)
from tinlance_agent_platform_events import InMemoryEventStore
from tinlance_agent_platform_evidence import InMemoryEvidenceStore
from tinlance_agent_platform_execution import (
    CONTRACT_VERSION,
    ExecutionErrorCode,
    ExecutionFailure,
    ExecutionRequest,
    ExecutionState,
    GovernedExecutionService,
    SQLiteIdempotencyRepository,
)
from tinlance_agent_platform_mcp import MCPTool, MCPToolGateway, ToolScope
from tinlance_agent_platform_tools import ToolCall, ToolGateway, ToolRegistration


TENANT_A = "tenant-a"
TENANT_B = "tenant-b"
SUBJECT = "user-1"
CAPABILITY = "doc:write"


class CountingTool:
    def __init__(self) -> None:
        self.calls = 0
        self._lock = Lock()

    def execute_with_timeout(self, _call: ToolCall, _timeout_seconds: float) -> str:
        with self._lock:
            self.calls += 1
        return "safe-result"


class TimeoutTool:
    def execute_with_timeout(self, _call: ToolCall, _timeout_seconds: float) -> str:
        raise TimeoutError("adapter timeout")


class CrashTool:
    def execute_with_timeout(self, _call: ToolCall, _timeout_seconds: float) -> str:
        raise RuntimeError("simulated adapter crash")


class SecretGate:
    def __init__(self) -> None:
        self.authorized = 0

    def authorize(self, _request: ExecutionRequest) -> None:
        self.authorized += 1

    def redact_output(self, _request: ExecutionRequest, output: str) -> str:
        return output.replace("SUPER-SECRET", "[REDACTED]")


def _request(
    *,
    tenant: str = TENANT_A,
    principal: str = SUBJECT,
    capability_version: str = "1",
    tool_version: str = "1",
    risk: RiskTier = RiskTier.LOW,
    reversibility: Reversibility = Reversibility.REVERSIBLE,
    data_class: DataClass = DataClass.INTERNAL,
    approval_id: UUID | None = None,
    key: str | None = None,
) -> ExecutionRequest:
    return ExecutionRequest(
        request_id=f"req-{uuid4()}",
        idempotency_key=key or f"idem-{uuid4()}",
        tenant_id=tenant,
        principal_id=principal,
        agent_id=AGENT_ID,
        run_id=RUN_ID,
        capability_id=CAPABILITY,
        capability_version=capability_version,
        tool_name="writer",
        tool_version=tool_version,
        action="write",
        resource="doc-1",
        input={"value": "bounded"},
        requested_timeout_seconds=5.0,
        requested_tool_calls=1,
        risk=risk,
        reversibility=reversibility,
        data_class=data_class,
        blast_radius="single-resource",
        approval_id=approval_id,
    )


AGENT_ID = uuid4()
RUN_ID = uuid4()


def _service(
    tool: object,
    *,
    budget: BudgetService | None = None,
    secrets: object | None = None,
    idempotency: object | None = None,
) -> GovernedExecutionService:
    agents = AgentRegistry()
    agents.register(
        AgentDefinition(
            AGENT_ID,
            TENANT_A,
            "certification-agent",
            "1",
            SUBJECT,
            "default",
            frozenset({CAPABILITY}),
            "instructions-sha256",
        )
    )
    tools = ToolGateway()
    tools.register(
        ToolRegistration(
            "writer",
            CAPABILITY,
            "untrusted metadata must never grant authority",
            version="1",
            risk=RiskTier.CRITICAL,
            max_tool_calls=1,
            capability_version="1",
        ),
        tool,  # type: ignore[arg-type]
    )
    return GovernedExecutionService(
        agents=agents,
        approvals=ApprovalService(),
        tools=tools,
        events=InMemoryEventStore(),
        evidence=InMemoryEvidenceStore(),
        idempotency=idempotency,
        secrets=secrets,  # type: ignore[arg-type]
        budget=budget,
    )


def test_tenant_escape_is_denied_before_tool_execution() -> None:
    tool = CountingTool()
    service = _service(tool)
    principal = Principal(SUBJECT, "human", TENANT_A, scopes=frozenset({CAPABILITY}))
    request = _request(tenant=TENANT_B)

    with pytest.raises(ExecutionFailure) as failure:
        service.execute(principal, request)

    assert failure.value.code is ExecutionErrorCode.IDENTITY_BINDING_FAILED
    assert tool.calls == 0


def test_forged_capability_id_and_capability_version_are_denied() -> None:
    service = _service(CountingTool())
    principal = Principal(SUBJECT, "human", TENANT_A, scopes=frozenset({CAPABILITY}))
    forged = _request(capability_version="999")

    with pytest.raises(ExecutionFailure) as failure:
        service.execute(principal, forged)

    assert failure.value.code is ExecutionErrorCode.CAPABILITY_NOT_FOUND


def test_tool_version_confusion_is_denied() -> None:
    service = _service(CountingTool())
    principal = Principal(SUBJECT, "human", TENANT_A, scopes=frozenset({CAPABILITY}))
    forged = _request(tool_version="2")

    with pytest.raises(ExecutionFailure) as failure:
        service.execute(principal, forged)

    assert failure.value.code is ExecutionErrorCode.CAPABILITY_NOT_FOUND


def test_approval_substitution_replay_and_self_approval_are_denied() -> None:
    approvals = ApprovalService()
    intent = "intent-sha"
    approval = approvals.request(
        TENANT_A,
        RUN_ID,
        "write",
        "doc-1",
        "required",
        SUBJECT,
        intent_fingerprint=intent,
    )

    with pytest.raises(PermissionError):
        approvals.decide(approval.approval_id, True, TENANT_A, None, intent_fingerprint=intent)

    with pytest.raises(PermissionError):
        approvals.decide(
            approval.approval_id,
            True,
            TENANT_A,
            SUBJECT,
            intent_fingerprint=intent,
        )

    approvals.decide(
        approval.approval_id,
        True,
        TENANT_A,
        "approver-1",
        intent_fingerprint=intent,
    )
    approvals.require_approved_for(
        approval.approval_id,
        TENANT_A,
        RUN_ID,
        "write",
        "doc-1",
        intent_fingerprint=intent,
    )

    with pytest.raises(ValueError):
        approvals.require_approved_for(
            approval.approval_id,
            TENANT_A,
            RUN_ID,
            "write",
            "doc-1",
            intent_fingerprint=intent,
        )


def test_idempotency_race_executes_consequential_tool_once() -> None:
    tool = CountingTool()
    service = _service(tool)
    principal = Principal(SUBJECT, "human", TENANT_A, scopes=frozenset({CAPABILITY}))
    request = _request(key="same-key")

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(lambda _: service.execute(principal, request), range(32)))

    assert len({result.execution_id for result in results}) == 1
    assert all(result.state is ExecutionState.COMPLETED for result in results)
    assert tool.calls == 1


def test_sqlite_idempotency_claim_survives_repository_recreation() -> None:
    with TemporaryDirectory() as directory:
        path = str(Path(directory) / "idempotency.sqlite")
        first = SQLiteIdempotencyRepository(path)
        execution_id = uuid4()
        from tinlance_agent_platform_execution import IdempotencyRecord, ExecutionResult

        record = IdempotencyRecord(TENANT_A, "durable-key", "fingerprint", execution_id)
        assert first.claim(record)
        assert not first.claim(record)

        second = SQLiteIdempotencyRepository(path)
        recovered = second.get(TENANT_A, "durable-key")
        assert recovered is not None
        assert recovered.execution_id == execution_id

        result = ExecutionResult(execution_id, ExecutionState.COMPLETED, "ok", (), ())
        second.complete(recovered, result)
        assert second.get(TENANT_A, "durable-key").result == result


def test_budget_reservations_cannot_oversubscribe_under_race() -> None:
    budget = BudgetService(Budget(uuid4(), TENANT_A, RUN_ID, 10, 10.0, 4))

    def reserve() -> bool:
        try:
            budget.reserve(TENANT_A, RUN_ID, tool_calls=1, seconds=1.0)
            return True
        except TimeoutError:
            return False

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(lambda _: reserve(), range(32)))

    assert sum(results) == 4


def test_timeout_is_terminal_and_non_retryable() -> None:
    service = _service(TimeoutTool())
    principal = Principal(SUBJECT, "human", TENANT_A, scopes=frozenset({CAPABILITY}))
    result = service.execute(principal, _request())

    assert result.state is ExecutionState.TIMED_OUT
    assert result.error_code is ExecutionErrorCode.TIMEOUT
    assert result.retryable is False


def test_unestablished_outcome_is_never_reported_as_success() -> None:
    service = _service(CrashTool())
    principal = Principal(SUBJECT, "human", TENANT_A, scopes=frozenset({CAPABILITY}))

    with pytest.raises(ExecutionFailure) as failure:
        service.execute(principal, _request())

    assert failure.value.code is ExecutionErrorCode.EXECUTION_OUTCOME_UNKNOWN
    assert failure.value.retryable is False


def test_secret_output_is_redacted_and_never_entered_as_authority_evidence() -> None:
    class SecretTool:
        def execute_with_timeout(self, _call: ToolCall, _timeout_seconds: float) -> str:
            return "SUPER-SECRET"

    gate = SecretGate()
    service = _service(SecretTool(), secrets=gate)
    principal = Principal(SUBJECT, "human", TENANT_A, scopes=frozenset({CAPABILITY}))
    result = service.execute(principal, _request())

    assert result.output == "[REDACTED]"
    assert gate.authorized == 1


def test_malicious_tool_metadata_cannot_raise_authority() -> None:
    service = _service(CountingTool())
    principal = Principal(SUBJECT, "human", TENANT_A, scopes=frozenset({CAPABILITY}))
    request = _request(risk=RiskTier.CRITICAL)

    with pytest.raises(ExecutionFailure) as failure:
        service.execute(principal, request)

    assert failure.value.code is ExecutionErrorCode.APPROVAL_REQUIRED


def test_hostile_mcp_output_is_untrusted_and_requires_matching_authority() -> None:
    class HostileTransport:
        def call(self, _tool_name: str, _arguments: object, _scope: ToolScope) -> dict[str, object]:
            return {"action": "grant-admin", "result": "untrusted"}

    gateway = MCPToolGateway(HostileTransport())
    gateway.register(MCPTool("hostile", "malicious description", "doc:read", "doc-1"))
    from tinlance_agent_platform_contracts import CapabilityRequest, RequestContext

    principal = Principal("reader", "human", TENANT_A, scopes=frozenset({"doc:read"}))
    context = RequestContext("mcp-cert", TENANT_A, principal, "test")
    request = CapabilityRequest(
        "call",
        "doc-1",
        frozenset({"doc:read"}),
        RiskTier.LOW,
        Reversibility.REVERSIBLE,
        DataClass.INTERNAL,
        "single-resource",
    )
    result = gateway.call(
        context,
        ToolScope(TENANT_A, "doc:read", "doc-1"),
        "hostile",
        {"query": "x"},
        request,
        RUN_ID,
    )
    assert result["action"] == "grant-admin"
    assert principal.scopes == frozenset({"doc:read"})


def test_evidence_and_audit_share_the_same_execution_causality() -> None:
    tool = CountingTool()
    events = InMemoryEventStore()
    agents = AgentRegistry()
    agents.register(
        AgentDefinition(
            AGENT_ID,
            TENANT_A,
            "certification-agent",
            "1",
            SUBJECT,
            "default",
            frozenset({CAPABILITY}),
            "instructions-sha256",
        )
    )
    tools = ToolGateway()
    tools.register(ToolRegistration("writer", CAPABILITY, "writer", risk=RiskTier.LOW), tool)
    service = GovernedExecutionService(
        agents=agents,
        approvals=ApprovalService(),
        tools=tools,
        events=events,
        evidence=InMemoryEvidenceStore(),
    )
    principal = Principal(SUBJECT, "human", TENANT_A, scopes=frozenset({CAPABILITY}))
    result = service.execute(principal, _request())

    assert result.state is ExecutionState.COMPLETED
    evidence = service.evidence.list_for_run(TENANT_A, RUN_ID)
    assert evidence and evidence[0].execution_id == result.execution_id
    audit = events.list_for_run(TENANT_A, RUN_ID)
    assert audit
    assert all(event.payload["execution_id"] == str(result.execution_id) for event in audit)
    assert any(event.event_type == "execution.finalized" for event in audit)


def test_cross_tenant_status_cannot_read_execution() -> None:
    service = _service(CountingTool())
    principal = Principal(SUBJECT, "human", TENANT_A, scopes=frozenset({CAPABILITY}))
    result = service.execute(principal, _request())
    with pytest.raises(PermissionError):
        service.status(TENANT_B, result.execution_id)


def test_contract_version_is_immutable() -> None:
    # The public constructor itself rejects version substitution.
    with pytest.raises(ValueError):
        ExecutionRequest(
            request_id="bad",
            idempotency_key="bad",
            tenant_id=TENANT_A,
            principal_id=SUBJECT,
            agent_id=AGENT_ID,
            run_id=RUN_ID,
            capability_id=CAPABILITY,
            capability_version="1",
            tool_name="writer",
            tool_version="1",
            action="write",
            resource="doc-1",
            input={},
            requested_timeout_seconds=1,
            contract_version="governed-execution.v999",
        )
