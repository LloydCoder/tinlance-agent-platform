from __future__ import annotations

import json
import unittest
from collections.abc import Mapping
from typing import Any
from uuid import uuid4

from tinlance_agent_platform_contracts import (
    CapabilityRequest,
    DataClass,
    Decision,
    Principal,
    RequestContext,
    Reversibility,
    RiskTier,
)
from tinlance_agent_platform_mcp import (
    MCPToolGateway,
    TWIHTTPTransport,
    TWIHTTPResponse,
    TWI_TOOL_REGISTRATIONS,
    TWITransportError,
    ToolScope,
    register_twi_tools,
)


TRACEPARENT = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
EXPORT_CAPABILITY = "world-intelligence.source-evidence.export"
EXPORT_RESOURCE = "world-intelligence://source-evidence/*"


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
        request_id: str,
        traceparent: str | None,
        expires_in_seconds: int,
    ) -> str:
        self.calls.append(
            {
                "tenant_id": tenant_id,
                "subject_id": subject_id,
                "audience": audience,
                "scopes": scopes,
                "request_id": request_id,
                "traceparent": traceparent,
                "expires_in_seconds": expires_in_seconds,
            }
        )
        return "platform-minted-twi-token"


class FakeHTTPClient:
    def __init__(
        self,
        response: TWIHTTPResponse | None = None,
    ) -> None:
        self.response = response or TWIHTTPResponse(
            201,
            {"content-type": "application/json"},
            json.dumps(
                {
                    "evidence_id": "00000000-0000-0000-0000-000000000001",
                    "status": "candidate",
                    "replayed": False,
                }
            ).encode(),
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
    ) -> TWIHTTPResponse:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout_seconds": timeout_seconds,
            }
        )
        return self.response


class ApprovedIntent:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def require_approved_for(
        self,
        approval_id,
        tenant_id: str,
        run_id,
        action: str,
        resource: str,
        *,
        intent_fingerprint: str | None = None,
    ) -> None:
        self.calls.append(
            {
                "approval_id": approval_id,
                "tenant_id": tenant_id,
                "run_id": run_id,
                "action": action,
                "resource": resource,
                "intent_fingerprint": intent_fingerprint,
            }
        )


def _context(*, subject_id: str = "subject-a") -> RequestContext:
    principal = Principal(
        subject_id=subject_id,
        principal_type="user",
        tenant_id="tenant-a",
        scopes=frozenset({EXPORT_CAPABILITY}),
    )
    return RequestContext(
        request_id="twi-request-0001",
        tenant_id="tenant-a",
        principal=principal,
        environment="test",
    )


def _scope(*, subject_id: str = "subject-a", request_id: str = "twi-request-0001") -> ToolScope:
    return ToolScope(
        tenant_id="tenant-a",
        capability=EXPORT_CAPABILITY,
        resource=EXPORT_RESOURCE,
        subject_id=subject_id,
        request_id=request_id,
        traceparent=TRACEPARENT,
    )


def _capability_request(*, risk: RiskTier = RiskTier.HIGH) -> CapabilityRequest:
    return CapabilityRequest(
        action="submit",
        resource=EXPORT_RESOURCE,
        capabilities=frozenset({EXPORT_CAPABILITY}),
        risk=risk,
        reversibility=Reversibility.REVERSIBLE,
        data_class=DataClass.PUBLIC,
        blast_radius="single",
    )


def _arguments() -> dict[str, object]:
    return {
        "claim_id": "claim-001",
        "statement": "A verified statement from a captured source.",
        "job_id": "job-0000000000000001",
        "quote": "A verified quote from the captured source.",
        "idempotency_key": "source-evidence-export-0001",
    }


class TWIPlatformIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.issuer = FakeTokenIssuer()
        self.http = FakeHTTPClient()
        self.transport = TWIHTTPTransport(
            base_url="https://twi.internal",
            audience="tinlance-web-intelligence",
            token_issuer=self.issuer,
            http_client=self.http,
        )

    def test_registers_all_twi_tools_with_export_approval_gate(self) -> None:
        gateway = MCPToolGateway(self.transport)
        register_twi_tools(gateway)
        export = next(
            tool for tool in TWI_TOOL_REGISTRATIONS
            if tool.name == "twi_world_intelligence_export"
        )
        self.assertTrue(export.requires_approval)
        self.assertEqual(export.risk, RiskTier.HIGH)
        self.assertEqual(export.idempotency_argument, "idempotency_key")
        self.assertEqual(len(TWI_TOOL_REGISTRATIONS), 8)

    def test_export_is_blocked_without_human_approval_before_network_call(self) -> None:
        gateway = MCPToolGateway(self.transport)
        register_twi_tools(gateway)
        with self.assertRaisesRegex(PermissionError, "approved human review"):
            gateway.call(
                _context(),
                _scope(),
                "twi_world_intelligence_export",
                _arguments(),
                _capability_request(),
                uuid4(),
            )
        self.assertEqual(self.http.calls, [])
        self.assertEqual(self.issuer.calls, [])

    def test_approved_export_uses_minted_audience_token_and_tenant_subject_context(self) -> None:
        gateway = MCPToolGateway(self.transport)
        register_twi_tools(gateway)
        approvals = ApprovedIntent()
        result = gateway.call(
            _context(),
            _scope(),
            "twi_world_intelligence_export",
            _arguments(),
            _capability_request(),
            uuid4(),
            approval_id=uuid4(),
            approval_verifier=approvals,
            intent_fingerprint="intent-sha256",
        )
        self.assertEqual(result["status"], "candidate")
        self.assertEqual(len(approvals.calls), 1)
        self.assertEqual(self.issuer.calls[0]["tenant_id"], "tenant-a")
        self.assertEqual(self.issuer.calls[0]["subject_id"], "subject-a")
        self.assertEqual(self.issuer.calls[0]["audience"], "tinlance-web-intelligence")
        self.assertEqual(
            self.issuer.calls[0]["scopes"], frozenset({"twi:observations:export"})
        )
        request = self.http.calls[0]
        self.assertEqual(request["method"], "POST")
        self.assertEqual(
            request["url"],
            "https://twi.internal/v1/integrations/world-intelligence/exports",
        )
        self.assertEqual(
            request["headers"]["Authorization"], "Bearer platform-minted-twi-token"
        )
        self.assertNotIn("inbound-token", request["headers"]["Authorization"])
        self.assertEqual(
            request["headers"]["Idempotency-Key"], "source-evidence-export-0001"
        )
        self.assertNotIn(
            "idempotency_key", json.loads(request["body"].decode("utf-8"))
        )
        self.assertEqual(request["headers"]["X-Request-ID"], "twi-request-0001")
        self.assertEqual(request["headers"]["traceparent"], TRACEPARENT)

    def test_registered_risk_floor_prevents_caller_downgrade(self) -> None:
        gateway = MCPToolGateway(self.transport)
        register_twi_tools(gateway)
        decision = gateway.authorize(
            _context(),
            _scope(),
            "twi_world_intelligence_export",
            _capability_request(risk=RiskTier.LOW),
        )
        self.assertIs(decision.decision, Decision.DENY)
        self.assertEqual(self.http.calls, [])

    def test_subject_and_request_context_cannot_be_replaced(self) -> None:
        gateway = MCPToolGateway(self.transport)
        register_twi_tools(gateway)
        decision = gateway.authorize(
            _context(),
            _scope(subject_id="other-subject"),
            "twi_world_intelligence_export",
            _capability_request(),
        )
        self.assertIs(decision.decision, Decision.DENY)
        decision = gateway.authorize(
            _context(),
            _scope(request_id="forged-request"),
            "twi_world_intelligence_export",
            _capability_request(),
        )
        self.assertIs(decision.decision, Decision.DENY)
        self.assertEqual(self.issuer.calls, [])

    def test_missing_subject_scope_and_redirect_responses_fail_closed(self) -> None:
        with self.assertRaisesRegex(PermissionError, "authenticated subject/request scope"):
            self.transport.call(
                "twi_search",
                {"query": "query", "idempotency_key": "search-idempotency-0001"},
                ToolScope("tenant-a", "web.search", "web://search/*"),
            )
        redirect_http = FakeHTTPClient(TWIHTTPResponse(302, {"location": "https://evil.example"}, b""))
        redirect_transport = TWIHTTPTransport(
            base_url="https://twi.internal",
            audience="tinlance-web-intelligence",
            token_issuer=self.issuer,
            http_client=redirect_http,
        )
        with self.assertRaises(TWITransportError) as raised:
            redirect_transport.call(
                "twi_search",
                {"query": "query", "idempotency_key": "search-idempotency-0001"},
                ToolScope(
                    "tenant-a",
                    "web.search",
                    "web://search/*",
                    subject_id="subject-a",
                    request_id="twi-request-0002",
                ),
            )
        self.assertEqual(raised.exception.status_code, 302)
        self.assertEqual(len(redirect_http.calls), 1)

    def test_production_transport_requires_https_origin(self) -> None:
        with self.assertRaisesRegex(ValueError, "plain HTTP"):
            TWIHTTPTransport(
                base_url="http://twi.internal",
                audience="tinlance-web-intelligence",
                token_issuer=self.issuer,
                http_client=self.http,
            )
        with self.assertRaisesRegex(ValueError, "origin"):
            TWIHTTPTransport(
                base_url="https://twi.internal/untrusted/path",
                audience="tinlance-web-intelligence",
                token_issuer=self.issuer,
                http_client=self.http,
            )


if __name__ == "__main__":
    unittest.main()
