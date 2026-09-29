from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from uuid import uuid4

import pytest

from tinlance_agent_platform_agents import AgentRegistry
from tinlance_agent_platform_api import (
    AgentPlatformAPI,
    ReferencePlatformGateway,
    StaticPrincipalResolver,
)
from tinlance_agent_platform_api.http import serve
from tinlance_agent_platform_contracts import AgentDefinition, Principal
from tinlance_agent_platform_events import InMemoryEventStore
from tinlance_agent_platform_evidence import InMemoryEvidenceStore

TENANT = "tenant-a"
SUBJECT = "user-a"
TOKEN = "token-a"


def _request(
    url: str, body: dict[str, object], token: str = TOKEN
) -> tuple[int, dict[str, object]]:
    raw = json.dumps(body).encode()
    request = urllib.request.Request(
        url,
        data=raw,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "X-Request-ID": str(uuid4()),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def _gateway() -> tuple[AgentPlatformAPI, ReferencePlatformGateway]:
    registry = AgentRegistry()
    gateway = ReferencePlatformGateway(
        agents=registry,
        events=InMemoryEventStore(),
        evidence=InMemoryEvidenceStore(),
    )
    gateway.register_agent(
        AgentDefinition(
            uuid4(),
            TENANT,
            "security-agent",
            "1.0.0",
            SUBJECT,
            "default",
            frozenset({"repository.read", "security.scan"}),
            "a" * 64,
        )
    )
    return AgentPlatformAPI(gateway), gateway


def test_http_golden_path_and_evidence_references() -> None:
    api, _gateway_instance = _gateway()
    resolver = StaticPrincipalResolver(
        {TOKEN: Principal(SUBJECT, "user", TENANT, scopes=frozenset({"platform"}))}
    )
    server = serve(api, resolver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}/v1/agent-platform"
        status, response = _request(base, {
            "tenant_id": TENANT,
            "subject_id": SUBJECT,
            "operation": "health",
            "payload": {},
        })
        assert status == 200
        assert response["payload"] == {"ready": True}

        status, response = _request(base, {
            "tenant_id": TENANT,
            "subject_id": SUBJECT,
            "operation": "agents.list",
            "payload": {},
        })
        assert status == 200
        agent_id = response["payload"]["agents"][0]["agent_id"]

        status, response = _request(base, {
            "tenant_id": TENANT,
            "subject_id": SUBJECT,
            "operation": "capabilities.list",
            "payload": {"agent_id": agent_id},
        })
        assert status == 200
        assert {item["capability_id"] for item in response["payload"]["capabilities"]} == {
            "repository.read",
            "security.scan",
        }

        task_id = str(uuid4())
        status, response = _request(base, {
            "tenant_id": TENANT,
            "subject_id": SUBJECT,
            "operation": "runs.create",
            "payload": {
                "task_id": task_id,
                "agent_id": agent_id,
                "intent": "inspect repository",
            },
        })
        assert status == 200
        run_id = response["payload"]["run_id"]
        assert response["payload"]["state"] == "running"

        status, response = _request(base, {
            "tenant_id": TENANT,
            "subject_id": SUBJECT,
            "operation": "approvals.request",
            "payload": {
                "run_id": run_id,
                "action": "security.scan",
                "resource": "repo:example",
                "reason": "scan requires governed approval",
            },
        })
        assert status == 200
        assert response["payload"]["approval_id"]

        status, response = _request(base, {
            "tenant_id": TENANT,
            "subject_id": SUBJECT,
            "operation": "runs.events",
            "payload": {"run_id": run_id},
        })
        assert status == 200
        assert {item["event_type"] for item in response["payload"]["events"]} == {
            "run.created",
            "approval.requested",
        }

        status, response = _request(base, {
            "tenant_id": TENANT,
            "subject_id": SUBJECT,
            "operation": "runs.cancel",
            "payload": {"run_id": run_id},
        })
        assert status == 200
        assert response["payload"]["state"] == "cancelled"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_http_rejects_tenant_spoofing() -> None:
    api, _gateway_instance = _gateway()
    resolver = StaticPrincipalResolver(
        {TOKEN: Principal(SUBJECT, "user", TENANT, scopes=frozenset({"platform"}))}
    )
    server = serve(api, resolver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}/v1/agent-platform"
        status, response = _request(base, {
            "tenant_id": "tenant-attacker",
            "subject_id": SUBJECT,
            "operation": "health",
            "payload": {},
        })
        assert status == 403
        assert response == {"error": "forbidden"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_http_rejects_missing_authentication() -> None:
    api, _gateway_instance = _gateway()
    resolver = StaticPrincipalResolver({})
    server = serve(api, resolver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}/v1/agent-platform"
        raw = json.dumps({
            "tenant_id": TENANT,
            "subject_id": SUBJECT,
            "operation": "health",
            "payload": {},
        }).encode()
        request = urllib.request.Request(
            base,
            data=raw,
            headers={"Content-Type": "application/json", "X-Request-ID": str(uuid4())},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=2)
        assert error.value.code == 401
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
