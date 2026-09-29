from uuid import uuid4

import pytest
from tinlance_agent_platform_sdk import AgentPlatform, ApprovalRef, EvidenceRef, Run

from tinlance_reference_agents import EngineeringAgent, IntelligenceAgent, SecurityResearchAgent
from tinlance_reference_agents.base import EvidenceBackedConclusion


class UnusedTransport:
    pass


@pytest.fixture
def client() -> AgentPlatform:
    # Construction is enough for local workflow tests; network calls are not made.
    return AgentPlatform(
        base_url="https://platform.example",
        bearer_token="opaque-token",
        tenant_id="tenant-a",
        subject_id="user-a",
    )


@pytest.mark.parametrize(
    "factory",
    [SecurityResearchAgent, EngineeringAgent, IntelligenceAgent],
)
def test_reference_agents_are_domain_composers(factory, client):
    agent = factory(client)
    assert agent.name
    assert agent.tools.list()
    assert all(descriptor.capability for descriptor in agent.tools.list())


def test_security_plan_marks_mutation_as_approval_bound(client):
    agent = SecurityResearchAgent(client)
    plans = agent.plan_tools()
    write = next(plan for plan in plans if plan.descriptor.name == "repository.write")
    assert write.requires_approval is True
    assert write.risk == "high"
    assert write.requested_timeout_seconds == 30.0
    assert write.requested_tool_calls == 1
    assert write.evidence_required is True


def test_engineering_plan_uses_governed_execution_boundary(client):
    agent = EngineeringAgent(client)
    assert callable(agent.execute_tool)
    assert not hasattr(agent, "_executor")


def test_research_agent_rejects_empty_objective(client):
    agent = IntelligenceAgent(client)
    with pytest.raises(ValueError):
        agent.workflow("   ")


def test_workflow_approval_invariant(client):
    agent = EngineeringAgent(client)
    assert all(
        not step.requires_approval or step.consequential
        for step in agent.workflow("fix failing tests")
    )
    assert uuid4()


class FakeRuns:
    def __init__(self):
        self.run = Run(uuid4(), uuid4(), "created", uuid4())

    def create(self, task_id, agent_id, objective, request_id=None):
        return self.run

    def events(self, run_id):
        return ()

    def evidence(self, run_id):
        return ()


class FakeApprovals:
    def request(
        self,
        run_id,
        action,
        resource,
        reason,
        *,
        execution_intent=None,
        request_id=None,
        idempotency_key=None,
    ):
        assert execution_intent is not None
        return ApprovalRef(uuid4())


class FakeClient:
    def __init__(self):
        self.runs = FakeRuns()
        self.approvals = FakeApprovals()


def test_security_start_uses_sdk_run_contract():
    client = FakeClient()
    agent = SecurityResearchAgent(client)
    result = agent.start_research(
        task_id=uuid4(),
        agent_id=uuid4(),
        objective="investigate a repository",
        request_id="req-security",
    )
    assert result.run.run_id == client.runs.run.run_id


def test_engineering_start_uses_sdk_run_contract():
    client = FakeClient()
    agent = EngineeringAgent(client)
    result = agent.start_task(
        task_id=uuid4(),
        agent_id=uuid4(),
        objective="fix failing tests",
        request_id="req-engineering",
    )
    assert result.workflow[-1].requires_approval


def test_intelligence_start_uses_sdk_run_contract():
    client = FakeClient()
    agent = IntelligenceAgent(client)
    result = agent.start_research(
        task_id=uuid4(),
        agent_id=uuid4(),
        objective="research a demand signal",
        request_id="req-intelligence",
    )
    assert result.planned_tools[-1].requires_approval


def test_shared_approval_and_collection_use_sdk_contract():
    client = FakeClient()
    agent = SecurityResearchAgent(client)
    run = agent.start_research(
        task_id=uuid4(),
        agent_id=uuid4(),
        objective="inspect",
    )
    plan = next(item for item in agent.plan_tools() if item.descriptor.name == "repository.write")
    approval_id = agent.request_approval(
        run,
        plan=plan,
        arguments={"path": "README.md"},
        reason="mutation requires review",
        request_id="req-approval",
    )
    events, evidence = agent.collect(run)
    assert approval_id
    assert events == ()
    assert evidence == ()


def test_untrusted_input_rejects_non_text():
    from tinlance_reference_agents.base import reject_untrusted_instructions

    with pytest.raises(TypeError):
        reject_untrusted_instructions(object())


def test_evidence_backed_conclusion_accepts_platform_reference():
    ref = EvidenceRef(uuid4())
    conclusion = EvidenceBackedConclusion("supported", (ref,), "medium")
    assert conclusion.evidence == (ref,)
