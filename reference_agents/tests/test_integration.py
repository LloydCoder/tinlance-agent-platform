"""End-to-end reference-agent coverage against the authoritative R10 HTTP contract."""

from __future__ import annotations

from threading import Thread
from uuid import uuid4

import pytest

from tests.support.reference_gateway import (
    ReferencePlatformGateway,
    StaticPrincipalResolver,
)from tinlance_agent_platform_agents import AgentRegistry
from tinlance_agent_platform_api import AgentPlatformAPI
from tinlance_agent_platform_api.http import serve
from tinlance_agent_platform_approvals import ApprovalService
from tinlance_agent_platform_contracts import AgentDefinition, Principal
from tinlance_agent_platform_events import InMemoryEventStore
from tinlance_agent_platform_evidence import InMemoryEvidenceStore
from tinlance_agent_platform_sdk import AgentPlatform

from tinlance_reference_agents import EngineeringAgent, IntelligenceAgent, SecurityResearchAgent


@pytest.fixture
def integration_clients():
    tenant = "reference-tenant"
    subject = "reference-user"
    token = "reference-token"
    approver = "reference-approver"
    approver_token = "reference-approver-token"

    definitions = {
        "security": (
            uuid4(),
            "security-reference",
            frozenset({"repository.read", "security.scan", "repository.write"}),
        ),
        "engineering": (
            uuid4(),
            "engineering-reference",
            frozenset(
                {
                    "repository.read",
                    "ci.inspect",
                    "repository.write",
                    "pull_request.merge",
                    "deployment.trigger",
                }
            ),
        ),
        "intelligence": (
            uuid4(),
            "intelligence-reference",
            frozenset({"research.search", "research.source", "research.report", "external.action"}),
        ),
    }

    events = InMemoryEventStore()
    evidence = InMemoryEvidenceStore()
    gateway = ReferencePlatformGateway(
        agents=AgentRegistry(),
        approvals=ApprovalService(),
        events=events,
        evidence=evidence,
        approver_subjects=frozenset({approver}),
    )
    for name, (agent_id, display_name, capabilities) in definitions.items():
        gateway.register_agent(
            AgentDefinition(
                agent_id=agent_id,
                tenant_id=tenant,
                name=display_name,
                version="0.1.0",
                owner_subject_id=subject,
                policy_profile=f"reference-{name}",
                capabilities=capabilities,
                instructions_hash=f"sha256:reference-{name}-instructions",
            )
        )

    resolver = StaticPrincipalResolver(
        {
            token: Principal(subject, "user", tenant),
            approver_token: Principal(approver, "user", tenant),
        }
    )
    api = AgentPlatformAPI(gateway)
    server = serve(api, resolver)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base_url = f"http://{host}:{port}"
    client = AgentPlatform(
        base_url=base_url,
        bearer_token=token,
        tenant_id=tenant,
        subject_id=subject,
        allow_insecure_http=True,
    )
    approver_client = AgentPlatform(
        base_url=base_url,
        bearer_token=approver_token,
        tenant_id=tenant,
        subject_id=approver,
        allow_insecure_http=True,
    )
    try:
        yield client, approver_client, definitions
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


@pytest.mark.parametrize(
    ("factory", "definition", "plan_name", "arguments"),
    [
        (SecurityResearchAgent, "security", "repository.write", {"path": "README.md"}),
        (EngineeringAgent, "engineering", "repository.write", {"path": "src/app.py"}),
        (IntelligenceAgent, "intelligence", "external.action", {"target": "reference"}),
    ],
)
def test_reference_agents_complete_r10_approval_and_execution(
    integration_clients, factory, definition, plan_name, arguments
):
    client, approver_client, definitions = integration_clients
    agent_id = definitions[definition][0]
    agent = factory(client)
    run = (
        agent.start_research(
            task_id=uuid4(),
            agent_id=agent_id,
            objective="perform a governed reference task",
        )
        if factory is not EngineeringAgent
        else agent.start_task(
            task_id=uuid4(),
            agent_id=agent_id,
            objective="perform a governed reference task",
        )
    )
    plan = next(item for item in agent.plan_tools() if item.descriptor.name == plan_name)
    idempotency_key = str(uuid4())

    pending = agent.execute_tool(
        run,
        plan=plan,
        arguments=arguments,
        idempotency_key=idempotency_key,
    )
    assert pending.state == "waiting_approval"
    assert pending.execution_id

    approval_id = agent.request_approval(
        run,
        plan=plan,
        arguments=arguments,
        reason="reference-agent mutation requires explicit human approval",
    )
    decision = approver_client.approvals.decide(approval_id, True)
    assert decision.state == "approved"

    completed = agent.execute_tool(
        run,
        plan=plan,
        arguments=arguments,
        approval_id=approval_id,
        idempotency_key=idempotency_key,
    )
    assert completed.state == "completed"
    assert completed.output
    assert completed.evidence_ids
    assert completed.audit_event_ids

    status = client.executions.get(completed.execution_id)
    assert status.state == "completed"

    events, evidence = agent.collect(run)
    assert any(event.event_type == "approval.requested" for event in events)
    assert any(event.event_type == "approval.decided" for event in events)
    assert any(event.event_type == "execution.completed" for event in events)
    assert evidence


def test_r10_pending_execution_is_resumable_without_replay(integration_clients):
    client, _approver_client, definitions = integration_clients
    agent = SecurityResearchAgent(client)
    run = agent.start_research(
        task_id=uuid4(),
        agent_id=definitions["security"][0],
        objective="resume a governed operation",
    )
    plan = next(item for item in agent.plan_tools() if item.descriptor.name == "repository.write")
    key = str(uuid4())

    first = agent.execute_tool(run, plan=plan, arguments={"path": "README.md"}, idempotency_key=key)
    second = agent.execute_tool(
        run,
        plan=plan,
        arguments={"path": "README.md"},
        idempotency_key=key,
    )

    assert first.execution_id == second.execution_id
    assert first.state == second.state == "waiting_approval"
