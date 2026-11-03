from __future__ import annotations

import http.client
import json
import threading
from dataclasses import dataclass
from uuid import uuid4

from tinlance_agent_platform_api.http import API_VERSION, serve
from tinlance_agent_platform_api.service import APIRequest, APIResponse


@dataclass(frozen=True)
class Principal:
    tenant_id: str = "tenant-a"
    subject_id: str = "subject-a"
    principal_type: str = "user"
    scopes: frozenset[str] = frozenset({"twi:search"})


class Resolver:
    def resolve(self, token: str) -> Principal:
        if token != "valid-platform-token":
            raise PermissionError("invalid token")
        return Principal()


class API:
    def __init__(self) -> None:
        self.requests: list[APIRequest] = []

    def dispatch(self, request: APIRequest) -> APIResponse:
        self.requests.append(request)
        return APIResponse(
            "success",
            {"tenant_id": request.tenant_id, "subject_id": request.subject_id},
        )


def post(
    server: object,
    payload: dict[str, object],
) -> tuple[int, dict[str, object]]:
    address = getattr(server, "server_address")
    connection = http.client.HTTPConnection("127.0.0.1", address[1], timeout=3)
    try:
        connection.request(
            "POST",
            "/v1/agent-platform",
            body=json.dumps(payload),
            headers={
                "Authorization": "Bearer valid-platform-token",
                "Content-Type": "application/json",
                "X-Tinlance-API-Version": API_VERSION,
                "X-Request-ID": str(uuid4()),
            },
        )
        response = connection.getresponse()
        return response.status, json.loads(response.read().decode("utf-8"))
    finally:
        connection.close()


def test_platform_http_derives_tenant_and_subject_from_verified_principal() -> None:
    api = API()
    server = serve(api, Resolver(), host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, body = post(
            server,
            {
                "operation": "twi.jobs.create_search",
                "payload": {"query": "zero trust", "limit": 5},
            },
        )
        assert status == 200
        assert body == {
            "status": "success",
            "payload": {"tenant_id": "tenant-a", "subject_id": "subject-a"},
        }
        assert len(api.requests) == 1
        assert api.requests[0].tenant_id == "tenant-a"
        assert api.requests[0].subject_id == "subject-a"
        assert api.requests[0].authenticated_principal.tenant_id == "tenant-a"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_platform_http_rejects_client_supplied_identity_that_differs_from_verified_principal() -> None:
    api = API()
    server = serve(api, Resolver(), host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, body = post(
            server,
            {
                "tenant_id": "tenant-b",
                "operation": "twi.jobs.create_search",
                "payload": {"query": "zero trust", "limit": 5},
            },
        )
        assert status == 403
        assert body == {"error": "forbidden"}
        assert api.requests == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
