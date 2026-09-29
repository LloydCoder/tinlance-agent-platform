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
from tinlance_agent_platform_events import EventStore
from tinlance_agent_platform_evidence import EvidenceStore
from tinlance_agent_platform_sdk import AgentPlatform


@pytest.fixture
def integration_client():
    tenant = "reference-tenant"
    subject = "reference-user"
    token = "reference-token"
    agent_id = uuid4()
    events = EventStore()
    evidence = EvidenceStore()
    gateway = ReferencePlatformGateway(
        agents=AgentRegistry(),
        approvals=ApprovalService(),
        events=events,
        evidence=evidence,
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
    resolver = StaticPrincipalResolver({token: Principal(subject, "user", tenant)})
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
    try:
        yield client, agent_id
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_golden_contract_path(integration_client):
    client, agent_id = integration_client
    task_id = uuid4()

    listed = client.agents.list()
    assert any(item.agent_id == agent_id for item in listed)

    run = client.runs.create(task_id, agent_id, "inspect repository")
    approval = client.approvals.request(
        run.run_id,
        "repository.write",
        "repo:reference",
        "human review is required before repository mutation",
    )
    events = client.runs.events(run.run_id)
    evidence = client.runs.evidence(run.run_id)

    assert approval.approval_id
    assert any(event.event_type == "approval.requested" for event in events)
    assert evidence == ()

    # API 1.1 deliberately ends at approval request. There is no public approval
    # decision or tools.execute operation, so this test must not fake the remaining
    # execution path.
