from __future__ import annotations

import json
import unittest
from collections.abc import Mapping
from typing import Any
from uuid import uuid4

from tinlance_agent_platform_api.service import APIRequest, APIResponse
from tinlance_agent_platform_app.twi_api_handler import TWIAPIHandler
from tinlance_agent_platform_contracts import Principal
from tinlance_agent_platform_mcp import (
    TWI_MCP_TOOL_DEFINITIONS,
    MCPToolGateway,
    TWIHTTPResponse,
    TWIHTTPTransport,
    compute_twi_intent_fingerprint,
    register_twi_tools,
)


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
        return "minted-twi-audience-token"


class FakeHTTPClient:
    def __init__(self) -> None:
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
        return TWIHTTPResponse(
            202,
            {"content-type": "application/json"},
            b'{"job_id":"job-0000000000000001","status":"queued"}',
        )


class FakeDelegate:
    def __init__(self) -> None:
        self.requests: list[APIRequest] = []

    def handle(self, request: APIRequest) -> APIResponse:
        self.requests.append(request)
        return APIResponse("success", {"delegated": request.operation})


class FakeApprovalVerifier:
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


def _principal(*scopes: str) -> Principal:
    return Principal(
        subject_id="subject-a",
        principal_type="user",
        tenant_id="tenant-a",
        scopes=frozenset(scopes),
    )


class TWIAPIHandlerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.issuer = FakeTokenIssuer()
        self.http = FakeHTTPClient()
        self.gateway = MCPToolGateway(
            TWIHTTPTransport(
                base_url="https://twi.internal",
                audience="tinlance-web-intelligence",
                token_issuer=self.issuer,
                http_client=self.http,
            )
        )
        register_twi_tools(self.gateway)
        self.delegate = FakeDelegate()
        self.approvals = FakeApprovalVerifier()
        self.handler = TWIAPIHandler(
            delegate=self.delegate,
            gateway=self.gateway,
            approval_verifier=self.approvals,
            environment="test",
        )

    def test_search_operation_uses_authenticated_subject_and_minted_twi_token(self) -> None:
        request = APIRequest(
            tenant_id="tenant-a",
            subject_id="subject-a",
            operation="twi.jobs.create_search",
            payload={"query": "AI security", "limit": 5},
            request_id="platform-twi-search-0001",
            trace_id="0123456789abcdef0123456789abcdef",
            idempotency_key="search-idempotency-0001",
            authenticated_principal=_principal("web.search"),
        )
        response = self.handler.handle(request)
        self.assertEqual(response.status, "success")
        self.assertEqual(len(self.http.calls), 1)
        self.assertEqual(self.issuer.calls[0]["tenant_id"], "tenant-a")
        self.assertEqual(self.issuer.calls[0]["subject_id"], "subject-a")
        self.assertEqual(self.issuer.calls[0]["scopes"], frozenset({"twi:search"}))
        self.assertEqual(
            self.http.calls[0]["headers"]["Authorization"],
            "Bearer minted-twi-audience-token",
        )
        self.assertEqual(
            json.loads(self.http.calls[0]["body"].decode()),
            {"kind": "search", "payload": {"query": "AI security", "limit": 5}},
        )
        self.assertEqual(
            self.http.calls[0]["headers"]["Idempotency-Key"], "search-idempotency-0001"
        )
        self.assertTrue(
            self.issuer.calls[0]["traceparent"].startswith("00-0123456789abcdef0123456789abcdef-")
        )

    def test_export_requires_exact_intent_bound_human_approval(self) -> None:
        run_id = uuid4()
        approval_id = uuid4()
        business_arguments: dict[str, object] = {
            "claim_id": "claim-001",
            "statement": "A verified statement from a captured source.",
            "job_id": "job-0000000000000001",
            "quote": "A verified quote from the captured source.",
            "idempotency_key": "source-evidence-export-0001",
        }
        fingerprint = compute_twi_intent_fingerprint(
            tenant_id="tenant-a",
            subject_id="subject-a",
            run_id=str(run_id),
            tool_name="twi_world_intelligence_export",
            arguments=business_arguments,
        )
        request = APIRequest(
            tenant_id="tenant-a",
            subject_id="subject-a",
            operation="twi.world_intelligence.export_source_evidence",
            payload={
                **business_arguments,
                "run_id": str(run_id),
                "approval_id": str(approval_id),
                "intent_fingerprint": fingerprint,
            },
            request_id="platform-twi-export-0001",
            trace_id="0123456789abcdef0123456789abcdef",
            idempotency_key="source-evidence-export-0001",
            authenticated_principal=_principal("world-intelligence.source-evidence.export"),
        )
        response = self.handler.handle(request)
        self.assertEqual(response.status, "success")
        self.assertEqual(len(self.approvals.calls), 1)
        self.assertEqual(self.approvals.calls[0]["approval_id"], approval_id)
        self.assertEqual(self.approvals.calls[0]["run_id"], run_id)
        self.assertEqual(self.approvals.calls[0]["intent_fingerprint"], fingerprint)
        sent = json.loads(self.http.calls[0]["body"].decode())
        self.assertEqual(set(sent), {"claim_id", "statement", "job_id", "quote"})
        self.assertEqual(
            self.http.calls[0]["headers"]["Idempotency-Key"],
            "source-evidence-export-0001",
        )

    def test_export_rejects_a_changed_intent_fingerprint_before_network_call(self) -> None:
        request = APIRequest(
            tenant_id="tenant-a",
            subject_id="subject-a",
            operation="twi.world_intelligence.export_source_evidence",
            payload={
                "claim_id": "claim-001",
                "statement": "A verified statement.",
                "job_id": "job-0000000000000001",
                "quote": "A verified quote from the captured source.",
                "idempotency_key": "source-evidence-export-0001",
                "run_id": str(uuid4()),
                "approval_id": str(uuid4()),
                "intent_fingerprint": "0" * 64,
            },
            request_id="platform-twi-export-0002",
            idempotency_key="source-evidence-export-0001",
            authenticated_principal=_principal("world-intelligence.source-evidence.export"),
        )
        with self.assertRaisesRegex(PermissionError, "fingerprint does not match"):
            self.handler.handle(request)
        self.assertEqual(self.http.calls, [])
        self.assertEqual(self.approvals.calls, [])

    def test_twi_operation_requires_platform_capability_scope(self) -> None:
        request = APIRequest(
            tenant_id="tenant-a",
            subject_id="subject-a",
            operation="twi.jobs.create_search",
            payload={"query": "AI security", "limit": 5},
            request_id="platform-twi-search-0003",
            idempotency_key="search-idempotency-0003",
            authenticated_principal=_principal("unrelated.capability"),
        )
        with self.assertRaises(PermissionError):
            self.handler.handle(request)
        self.assertEqual(self.http.calls, [])
        self.assertEqual(self.issuer.calls, [])

    def test_non_twi_operations_are_delegated_without_mutation(self) -> None:
        request = APIRequest(
            tenant_id="tenant-a",
            subject_id="subject-a",
            operation="runs.read",
            payload={"run_id": "run-1"},
            request_id="platform-other-operation",
            authenticated_principal=_principal("web.search"),
        )
        response = self.handler.handle(request)
        self.assertEqual(response.payload, {"delegated": "runs.read"})
        self.assertEqual(len(self.delegate.requests), 1)
        self.assertEqual(self.http.calls, [])

    def test_remote_mcp_definition_marks_export_consequential_and_approval_bound(self) -> None:
        definitions = {item.name: item for item in TWI_MCP_TOOL_DEFINITIONS}
        export = definitions["twi_world_intelligence_export"]
        self.assertTrue(export.consequential)
        self.assertEqual(export.idempotency_argument, "idempotency_key")
        required = set(export.input_schema["required"])
        self.assertTrue(
            {"run_id", "approval_id", "intent_fingerprint", "idempotency_key"} <= required
        )


if __name__ == "__main__":
    unittest.main()
