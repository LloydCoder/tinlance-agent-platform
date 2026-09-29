"""Actual SDK -> Platform HTTP integration against the reference Platform implementation."""

# ruff: isort: skip_file

from __future__ import annotations

from threading import Thread
from uuid import uuid4

import pytest

from tests.support.reference_gateway import ReferencePlatformGateway, StaticPrincipalResolver
from tinlance_agent_platform_agents import AgentRegistry
from tinlance_agent_platform_api import AgentPlatformAPI
from tinlance_agent_platform_api.http import serve
from tinlance_agent_platform_approvals import ApprovalService
from tinlance_agent_platform_contracts import AgentDefinition, Principal
from tinlance_agent_platform_events import InMemoryEventStore
from tinlance_agent_platform_evidence import InMemoryEvidenceStore
from tinlance_agent_platform_sdk import AgentPlatform, ToolInvocation


@pytest.fixture
def integration_client():
    tenant = "reference-tenant"
    subject = "reference-user"
    token = "reference-token"
    approver = "reference-approver"
    approver_token = "reference-approver-token"
    agent_id = uuid4()
    events = InMemoryEventStore()
    evidence = InMemoryEvidenceStore()
    gateway = ReferencePlatformGateway(
        agents=AgentRegistry(),
        approvals=ApprovalService(),
        events=events,
        evidence=evidence,
        approver_subjects=frozenset({approver}),
    )
    gateway.register_agent(
        AgentDefinition(
            agent_id=agent_id,
            tenant_id=tenant,
            name="security-reference",
            version="0.1.0",
            owner_subject_id=subject,
            policy_profile="reference-security",
            capabilities=frozenset({"repository.read", "security.scan", "repository.write"}),
            instructions_hash="sha256:reference-security-instructions",
        )
    )
    resolver = StaticPrincipalResolver({
        token: Principal(subject, "user", tenant),
        approver_token: Principal(approver, "user", tenant),
    })
    api = AgentPlatformAPI(gateway)
    server = serve(api, resolver)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    client = AgentPlatform(
        base_url=f"http://{host}:{port}",
        bearer_token=token,
        tenant_id=tenant,
        subject_id=subject,
        allow_insecure_http=True,
    )
    approver_client = AgentPlatform(
        base_url=f"http://{host}:{port}",
        bearer_token=approver_token,
        tenant_id=tenant,
        subject_id=approver,
        allow_insecure_http=True,
    )
    try:
        yield client, approver_client, agent_id
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_golden_contract_path(integration_client):
    client, approver_client, agent_id = integration_client
    task_id = uuid4()

    listed = client.agents.list()
    assert any(item.agent_id == agent_id for item in listed)

    run = client.runs.create(task_id, agent_id, "inspect repository")
    approval = client.approvals.request(
        run.run_id,
        "read",
        "repo:reference",
        "human review is required before supervised execution",
    )
    decision = approver_client.approvals.decide(approval.approval_id, True)
    assert decision.state == "approved"

    execution = client.tools.execute(
        run.run_id,
        agent_id,
        ToolInvocation(
            tool_name="reference.echo",
            capability="repository.read",
            action="read",
            resource="repo:reference",
            arguments={"path": "README.md"},
        ),
        risk="high",
        approval_id=approval.approval_id,
        requested_timeout_seconds=5,
        idempotency_key=str(uuid4()),
    )
    assert execution.state == "completed"
    assert execution.output == "governed:reference.echo:read:repo:reference"
    assert execution.evidence_ids
    assert execution.audit_event_ids

    status = client.executions.get(execution.execution_id)
    assert status.state == "completed"

    events = client.runs.events(run.run_id)
    evidence = client.runs.evidence(run.run_id)
    assert any(event.event_type == "approval.requested" for event in events)
    assert any(event.event_type == "approval.decided" for event in events)
    assert any(event.event_type == "execution.completed" for event in events)
    assert evidence
