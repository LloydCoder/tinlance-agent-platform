import http.client
import json
import threading
from dataclasses import dataclass
from uuid import uuid4

from tinlance_agent_platform_api.http import serve
from tinlance_agent_platform_api.service import APIResponse
from tinlance_agent_platform_multi_agent import A2AProtocolService, AgentCard, AgentSkill


@dataclass(frozen=True)
class Principal:
    tenant_id: str = "tenant-a"
    subject_id: str = "subject-a"


class Resolver:
    def resolve(self, token: str) -> Principal:
        if token != "valid-token":
            raise PermissionError("invalid token")
        return Principal()


class CardSignatureVerifier:
    def verify(self, key_id: str, algorithm: str, signing_input: bytes, signature: str) -> bool:
        return (
            key_id == "trusted-key-1"
            and algorithm == "EdDSA"
            and bool(signing_input)
            and signature == "dmFsaWQtc2lnbmF0dXJl"
        )


class RateLimiter:
    def __init__(self, allowed: bool = True) -> None:
        self.allowed = allowed
        self.calls: list[tuple[str, str]] = []

    def allow(self, tenant_id: str, subject_id: str) -> bool:
        self.calls.append((tenant_id, subject_id))
        return self.allowed


class API:
    def __init__(self) -> None:
        self.requests = []
        self.run_id = str(uuid4())
        self.task_id = str(uuid4())

    def dispatch(self, request):
        self.requests.append(request)
        if request.operation == "runs.create":
            return APIResponse(
                "accepted",
                {
                    "run_id": self.run_id,
                    "task_id": self.task_id,
                    "agent_id": request.payload["agent_id"],
                    "state": "requested",
                },
            )
        if request.operation == "runs.events":
            return APIResponse(
                "ok",
                {"events": [{"event_type": "run.completed", "payload": {"state": "completed"}}]},
            )
        raise AssertionError(f"unexpected operation: {request.operation}")


def make_service(*, allowed: bool = True):
    api = API()
    resolver = Resolver()
    limiter = RateLimiter(allowed)
    card = AgentCard(
        uuid4(),
        "1.0",
        "tinlance-agent",
        "Governed Tinlance agent",
        "https://agent.example.test/a2a",
        (AgentSkill("text.work", "Handle text tasks", frozenset({"text:work"})),),
        ("bearer",),
        "1.0.0",
        "dmFsaWQtc2lnbmF0dXJl",
        "trusted-key-1",
        "EdDSA",
    )
    service = A2AProtocolService(api, resolver, limiter, card, CardSignatureVerifier())
    return service, api, resolver, limiter, card


def headers(method: str, **extra: str) -> dict[str, str]:
    return {
        "Content-Type": "application/a2a+json",
        "Authorization": "Bearer valid-token",
        "A2A-Version": "1.0",
        **extra,
    }


def request(method: str, params: dict[str, object], request_id: str = "request-1") -> bytes:
    return json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
    ).encode()


def decode(response):
    return json.loads(response.body.decode())


def message() -> dict[str, object]:
    return {
        "messageId": "message-001",
        "role": "user",
        "parts": [{"kind": "text", "text": "Summarize the report"}],
        "contextId": "context-001",
    }


def test_a2a_message_send_dispatches_authenticated_tenant_and_returns_task() -> None:
    service, api, _, limiter, card = make_service()
    response = service.handle(
        headers("message/send"),
        request("message/send", {"message": message()}),
    )
    assert response.status_code == 200
    result = decode(response)["result"]
    assert result["task"]["id"] == api.run_id
    assert result["task"]["status"]["state"] == "submitted"
    assert result["task"]["contextId"] == "context-001"
    dispatched = api.requests[0]
    assert dispatched.operation == "runs.create"
    assert dispatched.tenant_id == "tenant-a"
    assert dispatched.subject_id == "subject-a"
    assert dispatched.authenticated_principal.subject_id == "subject-a"
    assert dispatched.payload == {
        "task_id": dispatched.payload["task_id"],
        "agent_id": str(card.agent_id),
        "intent": "Summarize the report",
    }
    assert len(dispatched.idempotency_key) >= 16
    assert limiter.calls == [("tenant-a", "subject-a")]
    assert response.headers["Content-Type"] == "application/a2a+json"


def test_a2a_tasks_get_reenters_platform_and_returns_task_snapshot() -> None:
    service, api, _, _, _ = make_service()
    response = service.handle(
        headers("tasks/get"),
        request("tasks/get", {"id": api.run_id, "historyLength": 5}),
    )
    assert response.status_code == 200
    task = decode(response)["result"]
    assert task["id"] == api.run_id
    assert task["status"]["state"] == "completed"
    assert api.requests[0].operation == "runs.events"
    assert api.requests[0].payload == {"run_id": api.run_id}


def test_a2a_rejects_bad_auth_version_origin_and_non_text_parts() -> None:
    service, _, _, _, _ = make_service()
    body = request("message/send", {"message": message()})
    unauthorized = service.handle(
        headers("message/send", authorization="Bearer invalid"), body
    )
    assert unauthorized.status_code == 401
    unsupported = service.handle(headers("message/send", **{"a2a-version": "9.9"}), body)
    assert unsupported.status_code == 400
    assert service.handle(
        headers("message/send", origin="https://evil.example.test"), body
    ).status_code == 403
    invalid_message = {
        "message": {
            "messageId": "message-002",
            "role": "user",
            "parts": [{"kind": "file", "file": {"uri": "https://example.test/secret"}}],
        }
    }
    invalid_parts = service.handle(
        headers("message/send"), request("message/send", invalid_message)
    )
    assert invalid_parts.status_code == 400


def test_a2a_requires_rate_limit_and_rejects_duplicate_json_keys() -> None:
    limited, _, _, _, _ = make_service(allowed=False)
    assert limited.handle(
        headers("message/send"), request("message/send", {"message": message()})
    ).status_code == 429
    service, _, _, _, _ = make_service()
    duplicate = b'{"jsonrpc":"2.0","id":"x","id":"y","method":"tasks/get","params":{"id":"x"}}'
    assert service.handle(headers("tasks/get"), duplicate).status_code == 400


def test_http_server_mounts_a2a_and_publishes_signed_agent_card() -> None:
    service, api, resolver, _, card = make_service()
    server = serve(api, resolver, host="127.0.0.1", port=0, a2a_service=service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        connection = http.client.HTTPConnection(host, port, timeout=3)
        connection.request("GET", "/.well-known/agent-card.json")
        card_response = connection.getresponse()
        card_body = json.loads(card_response.read().decode())
        assert card_response.status == 200
        assert card_body["signatures"][0]["signature"] == "dmFsaWQtc2lnbmF0dXJl"
        assert card_body["supportedInterfaces"][0]["url"] == card.endpoint
        connection.close()

        connection = http.client.HTTPConnection(host, port, timeout=3)
        payload = request("message/send", {"message": message()})
        connection.request("POST", "/a2a", body=payload, headers=headers("message/send"))
        response = connection.getresponse()
        result = json.loads(response.read().decode())
        assert response.status == 200
        assert result["result"]["task"]["id"] == api.run_id
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_a2a_task_id_must_be_a_uuid() -> None:
    service, _, _, _, _ = make_service()
    response = service.handle(
        headers("tasks/get"),
        request("tasks/get", {"id": "not-a-uuid"}),
    )
    assert response.status_code == 200
    assert "error" in decode(response)


def test_a2a_idempotency_key_stabilizes_task_identity_across_request_ids() -> None:
    service, api, _, _, _ = make_service()
    shared_key = "a2a-idempotency-key-0001"
    first = service.handle(
        headers("message/send", **{"idempotency-key": shared_key}),
        request("message/send", {"message": message()}, "first-request"),
    )
    second = service.handle(
        headers("message/send", **{"idempotency-key": shared_key}),
        request("message/send", {"message": message()}, "retry-request"),
    )
    assert first.status_code == second.status_code == 200
    assert api.requests[0].payload["task_id"] == api.requests[1].payload["task_id"]
    assert api.requests[0].idempotency_key == api.requests[1].idempotency_key == shared_key
