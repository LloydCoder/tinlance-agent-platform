from uuid import uuid4

import pytest
from tinlance_agent_platform_sdk import AgentPlatform

from tinlance_reference_agents import EngineeringAgent, IntelligenceAgent, SecurityResearchAgent


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


def test_engineering_plan_has_no_local_executor(client):
    agent = EngineeringAgent(client)
    assert not hasattr(agent, "execute_tool")
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
