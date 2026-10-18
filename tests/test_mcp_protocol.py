import http.client
import json
import threading
from dataclasses import dataclass

from tinlance_agent_platform_api.http import serve
from tinlance_agent_platform_api.service import APIResponse
from tinlance_agent_platform_mcp import MCPProtocolService, MCPToolDefinition


@dataclass(frozen=True)
class Principal:
    tenant_id: str = "tenant-a"
    subject_id: str = "subject-a"


class Resolver:
    def resolve(self, token: str) -> Principal:
        if token != "valid-token":
            raise PermissionError("invalid token")
        return Principal()


class RateLimiter:
    def __init__(self, allowed: bool = True) -> None:
        self.allowed = allowed
        self.calls = []

    def allow(self, tenant_id: str, subject_id: str) -> bool:
        self.calls.append((tenant_id, subject_id))
        return self.allowed


class API:
    def __init__(self) -> None:
        self.requests = []

    def dispatch(self, request):
        self.requests.append(request)
        return APIResponse("ok", {"accepted": True})


def make_service(*, allowed: bool = True):
    api = API()
    limiter = RateLimiter(allowed)
    service = MCPProtocolService(
        api,
        Resolver(),
        (
            MCPToolDefinition(
                "search",
                "Search public web sources",
                "web.search",
                {
                    "type": "object",
                    "properties": {"query": {"type": "string", "maxLength": 100}},
                    "required": ["query"],
                    "additionalProperties": False,
                },
            ),
            MCPToolDefinition(
                "submit",
                "Submit a consequential operation",
                "runs.create",
                {
                    "type": "object",
                    "properties": {
                        "payload": {"type": "string", "maxLength": 100},
                        "idempotency_key": {"type": "string", "maxLength": 256},
                    },
                    "required": ["payload", "idempotency_key"],
                    "additionalProperties": False,
                },
                consequential=True,
                idempotency_argument="idempotency_key",
            ),
        ),
        allowed_origins=("https://client.example.test",),
        rate_limiter=limiter,
    )
    return service, api, limiter


def headers(method: str, **extra: str) -> dict[str, str]:
    return {
        "content-type": "application/json",
        "authorization": "Bearer valid-token",
        "mcp-protocol-version": "2026-07-28",
        "mcp-method": method,
        **extra,
    }


def body(method: str, params: dict[str, object] | None = None) -> bytes:
    request_params = dict(params or {})
    request_params.setdefault(
        "_meta",
        {"io.modelcontextprotocol/clientInfo": {"name": "tinlance-tests", "version": "1.0.0"}},
    )
    return json.dumps(
        {"jsonrpc": "2.0", "id": "request-1", "method": method, "params": request_params}
    ).encode()


def decode(response):
    return json.loads(response.body.decode())


def test_stateless_discovery_and_tools_list_are_cache_safe() -> None:
    service, _, _ = make_service()
    discovery = service.handle(headers("server/discover"), body("server/discover"))
    assert discovery.status_code == 200
    assert decode(discovery)["result"]["protocolVersion"] == "2026-07-28"
    listing = service.handle(headers("tools/list"), body("tools/list"))
    assert listing.status_code == 200
    result = decode(listing)["result"]
    assert [tool["name"] for tool in result["tools"]] == ["search", "submit"]
    assert result["cacheScope"] == "private"
    assert listing.headers["Cache-Control"] == "no-store"


def test_tool_call_binds_authenticated_tenant_and_validates_arguments() -> None:
    service, api, limiter = make_service()
    response = service.handle(
        headers("tools/call", **{"mcp-name": "search"}),
        body("tools/call", {"name": "search", "arguments": {"query": "weather"}}),
    )
    assert response.status_code == 200
    assert decode(response)["result"]["isError"] is False
    assert len(api.requests) == 1
    assert api.requests[0].tenant_id == "tenant-a"
    assert api.requests[0].subject_id == "subject-a"
    assert api.requests[0].operation == "web.search"
    assert api.requests[0].payload == {"query": "weather"}
    assert limiter.calls == [("tenant-a", "subject-a")]


def test_consequential_tool_requires_and_forwards_idempotency_key() -> None:
    service, api, _ = make_service()
    key = "operation-idempotency-001"
    response = service.handle(
        headers("tools/call", **{"mcp-name": "submit"}),
        body(
            "tools/call",
            {
                "name": "submit",
                "arguments": {"payload": "send", "idempotency_key": key},
            },
        ),
    )
    assert response.status_code == 200
    assert api.requests[0].idempotency_key == key
    assert api.requests[0].payload == {"payload": "send"}


def test_protocol_rejects_origin_header_mismatch_auth_and_rate_limit() -> None:
    service, _, _ = make_service()
    origin = service.handle(
        headers("tools/list", origin="https://evil.example.test"), body("tools/list")
    )
    assert origin.status_code == 403
    mismatch = service.handle(
        headers("tools/list", **{"mcp-method": "tools/call"}), body("tools/list")
    )
    assert mismatch.status_code == 200
    assert "error" in decode(mismatch)
    unauthorized_headers = headers("tools/list", authorization="Basic invalid")
    assert service.handle(unauthorized_headers, body("tools/list")).status_code == 401
    limited, _, _ = make_service(allowed=False)
    assert limited.handle(headers("tools/list"), body("tools/list")).status_code == 429


def test_protocol_rejects_invalid_versions_arguments_and_oversized_payloads() -> None:
    service, _, _ = make_service()
    invalid_version = service.handle(
        headers("tools/list", **{"mcp-protocol-version": "unknown"}), body("tools/list")
    )
    assert invalid_version.status_code == 400
    invalid_args = service.handle(
        headers("tools/call", **{"mcp-name": "search"}),
        body("tools/call", {"name": "search", "arguments": {"query": "ok", "extra": True}}),
    )
    assert invalid_args.status_code == 400
    assert service.handle(headers("tools/list"), b"x" * (1_048_576 + 1)).status_code == 413


def test_duplicate_json_keys_and_invalid_traceparent_fail_closed() -> None:
    service, _, _ = make_service()
    duplicate = b'{"jsonrpc":"2.0","id":"x","id":"y","method":"tools/list","params":{}}'
    assert service.handle(headers("tools/list"), duplicate).status_code == 400
    invalid_trace = service.handle(
        headers(
            "tools/call",
            **{"mcp-name": "search", "traceparent": "00-" + "0" * 32 + "-" + "2" * 16 + "-01"},
        ),
        body("tools/call", {"name": "search", "arguments": {"query": "ok"}}),
    )
    assert invalid_trace.status_code == 400


def test_http_server_mounts_the_mcp_service_at_the_remote_endpoint() -> None:
    service, api, _ = make_service()
    server = serve(api, Resolver(), host="127.0.0.1", port=0, mcp_service=service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        connection = http.client.HTTPConnection(host, port, timeout=3)
        payload = body("server/discover")
        connection.request(
            "POST",
            "/mcp",
            body=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer valid-token",
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "server/discover",
            },
        )
        response = connection.getresponse()
        decoded = json.loads(response.read().decode())
        assert response.status == 200
        assert decoded["result"]["protocolVersion"] == "2026-07-28"
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_protocol_requires_valid_per_request_client_metadata() -> None:
    service, _, _ = make_service()
    missing = json.dumps(
        {"jsonrpc": "2.0", "id": "missing-meta", "method": "tools/list", "params": {}}
    ).encode()
    assert service.handle(headers("tools/list"), missing).status_code == 400
    invalid = body(
        "tools/list",
        {"_meta": {"io.modelcontextprotocol/clientInfo": {"name": " ", "version": "1.0"}}},
    )
    assert service.handle(headers("tools/list"), invalid).status_code == 400
