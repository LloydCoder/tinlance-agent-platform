from uuid import uuid4

from tinlance_agent_platform_agents import AgentRegistry
from tinlance_agent_platform_approvals import ApprovalService
from tinlance_agent_platform_budgets import BudgetService
from tinlance_agent_platform_context import ContextService
from tinlance_agent_platform_evaluation import EvalCase, EvalRunner
from tinlance_agent_platform_governance import CapabilityGrant, GovernanceService
from tinlance_agent_platform_mcp import MCPTool, MCPToolGateway, ToolScope
from tinlance_agent_platform_multi_agent import DelegationService
from tinlance_agent_platform_observability import InMemoryObservabilitySink
from tinlance_agent_platform_operations import Config, OperationsService
from tinlance_agent_platform_trajectory.chain import InMemoryTrajectoryStore


def test_m14_conformance_surfaces_are_available() -> None:
    assert AgentRegistry and ApprovalService and BudgetService
    assert ContextService and EvalRunner and GovernanceService
    assert MCPTool and MCPToolGateway and ToolScope
    assert DelegationService and InMemoryObservabilitySink
    assert Config and OperationsService and InMemoryTrajectoryStore


def test_m14_cross_cutting_fail_closed_invariants() -> None:
    service = GovernanceService()
    agent = uuid4()
    service.grant(CapabilityGrant("t1", agent, "read", "repo:a"))
    assert service.authorize("t1", agent, "read", "repo:a")
    service.stop_tenant("t1")
    assert not service.authorize("t1", agent, "read", "repo:a")
    eval_runner = EvalRunner(lambda value: value)
    assert eval_runner.run(EvalCase("release", "ok", "ok")).passed
