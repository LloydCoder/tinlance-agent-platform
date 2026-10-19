from __future__ import annotations

import unittest
from collections.abc import Mapping
from typing import Any

from tinlance_agent_platform_app.world_intelligence_api_handler import WorldIntelligenceAPIHandler
from tinlance_agent_platform_api.service import APIRequest, APIResponse
from tinlance_agent_platform_contracts import Principal
from tinlance_agent_platform_mcp import (
    MCPToolGateway,
    ToolScope,
    WorldIntelligenceHTTPResponse,
    WorldIntelligenceHTTPTransport,
    WorldIntelligenceTransportError,
    register_world_intelligence_tools,
)

TRACE_ID = "0123456789abcdef0123456789abcdef"
TRACEPARENT = f"00-{TRACE_ID}-0123456789abcdef-01"
ENTITY_CAPABILITY = "world-intelligence.query_entity"
PURPOSE_SCOPE = "world-intelligence:purpose:account_research"
ENTITY_RESOURCE = "world-intelligence://entities"


class FakeTokenIssuer:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def issue_token(
        self,
        *,
        tenant_id: str,
        subject_id: str,
        audience: str,
        scopes: frozenset[str],
        purpose: str,
        request_id: str,
        traceparent: str | None,
        expires_in_seconds: int,
    ) -> str:
        self.calls.append({
            "tenant_id": tenant_id,
            "subject_id": subject_id,
            "audience": audience,
            "scopes": scopes,
            "purpose": purpose,
            "request_id": request_id,
            "traceparent": traceparent,
            "expires_in_seconds": expires_in_seconds,
        })
        return "platform-minted-world-intelligence-token"


class FakeHTTPClient:
    def __init__(self, response: WorldIntelligenceHTTPResponse | None = None) -> None:
        self.response = response or WorldIntelligenceHTTPResponse(
            200,
            {"content-type": "application/json"},
            b'{"items":[{"id":"entity-1"}],"next_cursor":null,"total":1}',
        )
        self.calls: list[dict[str, Any]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> WorldIntelligenceHTTPResponse:
        self.calls.append({
            "method": method,
            "url": url,
            "headers": dict(headers),
            "body": body,
            "timeout_seconds": timeout_seconds,
        })
        return self.response


class FakeDelegate:
    def __init__(self) -> None:
        self.requests: list[APIRequest] = []

    def handle(self, request: APIRequest) -> APIResponse:
        self.requests.append(request)
        return APIResponse("success", {"delegated": request.operation})


def _principal(*scopes: str) -> Principal:
    return Principal(
        subject_id="subject-a",
        principal_type="agent",
        tenant_id="tenant-a",
        scopes=frozenset(scopes),
    )


def _scope(*, subject_id: str = "subject-a") -> ToolScope:
    return ToolScope(
        tenant_id="tenant-a",
        capability=ENTITY_CAPABILITY,
        resource=ENTITY_RESOURCE,
        subject_id=subject_id,
        request_id="platform-wi-query-0001",
        traceparent=TRACEPARENT,
    )


class WorldIntelligenceTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.issuer = FakeTokenIssuer()
        self.http = FakeHTTPClient()
        self.transport = WorldIntelligenceHTTPTransport(
            base_url="https://world-intelligence.internal",
            audience="world-intelligence",
            token_issuer=self.issuer,
            http_client=self.http,
        )

    def test_query_uses_platform_token_with_bound_identity_purpose_and_trace(self) -> None:
        result = self.transport.call(
            "world_intelligence_query_entities",
            {"purpose": "account_research", "limit": 10, "cursor": 0},
            _scope(),
        )
        self.assertEqual(result["items"], [{"id": "entity-1"}])
        self.assertEqual(self.issuer.calls[0]["tenant_id"], "tenant-a")
        self.assertEqual(self.issuer.calls[0]["subject_id"], "subject-a")
        self.assertEqual(self.issuer.calls[0]["audience"], "world-intelligence")
        self.assertEqual(self.issuer.calls[0]["purpose"], "account_research")
        self.assertEqual(self.issuer.calls[0]["scopes"], frozenset({"world-intelligence:query"}))
        self.assertEqual(self.issuer.calls[0]["expires_in_seconds"], 60)
        sent = self.http.calls[0]
        self.assertEqual(sent["method"], "GET")
        self.assertEqual(
            sent["url"],
            "https://world-intelligence.internal/v1/entities?limit=10&cursor=0",
        )
        self.assertIsNone(sent["body"])
        self.assertEqual(
            sent["headers"]["Authorization"],
            "Bearer platform-minted-world-intelligence-token",
        )
        self.assertEqual(sent["headers"]["X-Tinlance-Tenant-ID"], "tenant-a")
        self.assertEqual(sent["headers"]["X-Tinlance-Subject-ID"], "subject-a")
        self.assertEqual(sent["headers"]["X-Tinlance-Purpose"], "account_research")
        self.assertEqual(sent["headers"]["traceparent"], TRACEPARENT)

    def test_transport_rejects_unbound_scope_and_invalid_query(self) -> None:
        with self.assertRaises(PermissionError):
            self.transport.call(
                "world_intelligence_query_entities",
                {"purpose": "account_research"},
                ToolScope("tenant-a", ENTITY_CAPABILITY, ENTITY_RESOURCE),
            )
        with self.assertRaises(ValueError):
            self.transport.call(
                "world_intelligence_query_entities",
                {"purpose": "Marketing"},
                _scope(),
            )
        with self.assertRaises(ValueError):
            self.transport.call(
                "world_intelligence_query_entities",
                {"purpose": "account_research", "limit": 1001},
                _scope(),
            )
        with self.assertRaises(ValueError):
            self.transport.call(
                "world_intelligence_query_entities",
                {"purpose": "account_research", "tenant_id": "tenant-b"},
                _scope(),
            )
        self.assertEqual(self.http.calls, [])
        self.assertEqual(self.issuer.calls, [])

    def test_transport_rejects_redirects_and_malformed_response(self) -> None:
        redirect = WorldIntelligenceHTTPTransport(
            base_url="https://world-intelligence.internal",
            audience="world-intelligence",
            token_issuer=self.issuer,
            http_client=FakeHTTPClient(
                WorldIntelligenceHTTPResponse(
                    302, {"location": "https://evil.example"}, b""
                )
            ),
        )
        with self.assertRaises(WorldIntelligenceTransportError) as caught:
            redirect.call(
                "world_intelligence_query_entities",
                {"purpose": "account_research"},
                _scope(),
            )
        self.assertFalse(caught.exception.retryable)
        malformed = WorldIntelligenceHTTPTransport(
            base_url="https://world-intelligence.internal",
            audience="world-intelligence",
            token_issuer=self.issuer,
            http_client=FakeHTTPClient(
                WorldIntelligenceHTTPResponse(
                    200,
                    {"content-type": "application/json"},
                    b'{"items":"not-an-array"}',
                )
            ),
        )
        with self.assertRaises(WorldIntelligenceTransportError):
            malformed.call(
                "world_intelligence_query_entities",
                {"purpose": "account_research"},
                _scope(),
            )

    def test_transient_http_failure_is_retryable_and_authorization_failure_is_not(self) -> None:
        for status_code, retryable in ((503, True), (403, False)):
            transport = WorldIntelligenceHTTPTransport(
                base_url="https://world-intelligence.internal",
                audience="world-intelligence",
                token_issuer=self.issuer,
                http_client=FakeHTTPClient(
                    WorldIntelligenceHTTPResponse(
                        status_code, {"content-type": "application/json"}, b"{}"
                    )
                ),
            )
            with self.subTest(status_code=status_code):
                with self.assertRaises(WorldIntelligenceTransportError) as caught:
                    transport.call(
                        "world_intelligence_query_entities",
                        {"purpose": "account_research"},
                        _scope(),
                    )
                self.assertEqual(caught.exception.retryable, retryable)

    def test_production_transport_requires_https_and_exact_audience(self) -> None:
        with self.assertRaises(ValueError):
            WorldIntelligenceHTTPTransport(
                base_url="http://world-intelligence.internal",
                audience="world-intelligence",
                token_issuer=self.issuer,
                http_client=self.http,
            )
        with self.assertRaises(ValueError):
            WorldIntelligenceHTTPTransport(
                base_url="https://world-intelligence.internal",
                audience="other-service",
                token_issuer=self.issuer,
                http_client=self.http,
            )


class WorldIntelligenceAPIHandlerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.issuer = FakeTokenIssuer()
        self.http = FakeHTTPClient()
        self.gateway = MCPToolGateway(WorldIntelligenceHTTPTransport(
            base_url="https://world-intelligence.internal",
            audience="world-intelligence",
            token_issuer=self.issuer,
            http_client=self.http,
        ))
        register_world_intelligence_tools(self.gateway)
        self.delegate = FakeDelegate()
        self.handler = WorldIntelligenceAPIHandler(
            delegate=self.delegate,
            gateway=self.gateway,
            environment="test",
        )

    def test_handler_requires_platform_capability_and_authorized_purpose(self) -> None:
        request = APIRequest(
            tenant_id="tenant-a",
            subject_id="subject-a",
            operation="world_intelligence.query_entities",
            payload={"purpose": "account_research", "limit": 5},
            request_id="platform-wi-query-0001",
            trace_id=TRACE_ID,
            authenticated_principal=_principal(ENTITY_CAPABILITY),
        )
        with self.assertRaisesRegex(PermissionError, "not authorized for the requested purpose"):
            self.handler.handle(request)
        self.assertEqual(self.http.calls, [])
        self.assertEqual(self.issuer.calls, [])

    def test_handler_requires_resource_capability_before_network_call(self) -> None:
        request = APIRequest(
            tenant_id="tenant-a",
            subject_id="subject-a",
            operation="world_intelligence.query_entities",
            payload={"purpose": "account_research"},
            request_id="platform-wi-query-missing-capability",
            trace_id=TRACE_ID,
            authenticated_principal=_principal(PURPOSE_SCOPE),
        )
        with self.assertRaises(PermissionError):
            self.handler.handle(request)
        self.assertEqual(self.http.calls, [])
        self.assertEqual(self.issuer.calls, [])

    def test_handler_routes_authorized_query_through_platform_gateway(self) -> None:
        request = APIRequest(
            tenant_id="tenant-a",
            subject_id="subject-a",
            operation="world_intelligence.query_entities",
            payload={"purpose": "account_research", "limit": 5},
            request_id="platform-wi-query-0002",
            trace_id=TRACE_ID,
            authenticated_principal=_principal(ENTITY_CAPABILITY, PURPOSE_SCOPE),
        )
        response = self.handler.handle(request)
        self.assertEqual(response.status, "success")
        self.assertEqual(response.payload["items"], [{"id": "entity-1"}])
        self.assertEqual(len(self.http.calls), 1)

    def test_handler_rejects_identity_mismatch_and_delegates_other_operations(self) -> None:
        request = APIRequest(
            tenant_id="tenant-b",
            subject_id="subject-a",
            operation="world_intelligence.query_entities",
            payload={"purpose": "account_research"},
            request_id="platform-wi-query-0003",
            authenticated_principal=_principal(ENTITY_CAPABILITY, PURPOSE_SCOPE),
        )
        with self.assertRaisesRegex(PermissionError, "does not match request identity"):
            self.handler.handle(request)
        delegated = APIRequest(
            tenant_id="tenant-a",
            subject_id="subject-a",
            operation="runs.read",
            payload={},
            request_id="platform-wi-delegate",
            authenticated_principal=_principal(ENTITY_CAPABILITY),
        )
        response = self.handler.handle(delegated)
        self.assertEqual(response.payload, {"delegated": "runs.read"})
        self.assertEqual(self.http.calls, [])


if __name__ == "__main__":
    unittest.main()
