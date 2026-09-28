from uuid import uuid4
import pytest
from tinlance_agent_platform_agents import AgentRegistry
from tinlance_agent_platform_approvals import ApprovalService
from tinlance_agent_platform_budgets import BudgetService
from tinlance_agent_platform_contracts import AgentDefinition,ApprovalStatus,Budget,CapabilityRequest,DataClass,Decision,Principal,RequestContext,Reversibility,RiskTier,Run,RunStatus,SandboxRequest,ToolCall
from tinlance_agent_platform_runtime import InvalidTransition,RunStateMachine
from tinlance_agent_platform_sandbox import SandboxPolicy,SandboxUnavailable,validate_request
from tinlance_agent_platform_tools import ToolGateway,ToolRegistration

def test_agent_versions_are_immutable_and_tenant_scoped()->None:
    registry=AgentRegistry()
    agent=AgentDefinition(uuid4(),"t-a","fdse","1.0.0","owner","default",frozenset({"code:run"}),"h")
    registry.register(agent); registry.register(agent)
    with pytest.raises(ValueError): registry.register(AgentDefinition(agent.agent_id,"t-a","fdse","1.0.0","owner","other",agent.capabilities,"x"))
    with pytest.raises(KeyError): registry.get("t-b",agent.agent_id,"1.0.0")

def test_run_state_machine_is_fail_closed()->None:
    machine=RunStateMachine(); run=machine.transition(Run(uuid4(),uuid4(),"t-a"),RunStatus.RUNNING); run=machine.next_turn(run)
    assert run.turn_count==1
    with pytest.raises(InvalidTransition): machine.transition(run,RunStatus.SUCCEEDED)
    run=machine.transition(run,RunStatus.WAITING_APPROVAL)
    with pytest.raises(InvalidTransition): machine.transition(run,RunStatus.CREATED)

def test_approval_must_be_explicit()->None:
    service=ApprovalService(); approval=service.request("t-a",uuid4(),"delete","db:item","destructive","agent")
    with pytest.raises(PermissionError): service.require_approved(approval.approval_id)
    approved=service.decide(approval.approval_id,True)
    assert approved.status is ApprovalStatus.APPROVED
    service.require_approved(approval.approval_id)

def test_budget_is_hard_and_monotonic()->None:
    service=BudgetService(Budget(uuid4(),"t-a",uuid4(),2,10,1)); service.consume_turn(2); service.consume_tool_call()
    with pytest.raises(TimeoutError): service.consume_tool_call()
    with pytest.raises(TimeoutError): service.consume_turn(9)

def test_sandbox_fails_closed()->None:
    request=SandboxRequest(uuid4(),"t-a",uuid4(),"ws",("python",),10)
    with pytest.raises(SandboxUnavailable): validate_request(request,SandboxPolicy(frozenset({"python"})))
    with pytest.raises(PermissionError): validate_request(SandboxRequest(uuid4(),"t-a",uuid4(),"ws",("sh",),10,False,("/workspace",)),SandboxPolicy(frozenset({"python"})))

def test_tool_gateway_requires_authorization()->None:
    class Executor:
        def execute(self,call:ToolCall)->str:return "executed"
    gateway=ToolGateway(); gateway.register(ToolRegistration("read","doc:read","read"),Executor())
    principal=Principal("u","human","t-a",scopes=frozenset({"doc:read"})); context=RequestContext("r","t-a",principal,"test")
    call=ToolCall(uuid4(),"t-a",uuid4(),"read","doc:read","read","doc")
    request=CapabilityRequest("read","doc",frozenset({"doc:read"}),RiskTier.LOW,Reversibility.REVERSIBLE,DataClass.INTERNAL,"single")
    decision=gateway.authorize(context,call,request)
    assert decision.decision is Decision.ALLOW
    assert gateway.execute(call,decision)=="executed"
