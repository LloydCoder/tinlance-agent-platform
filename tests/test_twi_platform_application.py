from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from tinlance_agent_platform_api.service import APIRequest, APIResponse
from tinlance_agent_platform_app import create_twi_platform_application
from tinlance_agent_platform_contracts import Principal
from tinlance_agent_platform_mcp.twi import TWIHTTPResponse

ISSUER = "https://identity.tinlance.com/"
AUDIENCE = "tinlance-web-intelligence"
KMS_KEY_ID = "arn:aws:kms:eu-west-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class FakeKMS:
    def __init__(self) -> None:
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:
        assert KeyId == KMS_KEY_ID
        return {
            "KeyId": KMS_KEY_ID,
            "KeyUsage": "SIGN_VERIFY",
            "KeySpec": "RSA_2048",
            "SigningAlgorithms": ["RSASSA_PKCS1_V1_5_SHA_256"],
            "PublicKey": self.private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        }

    def sign(self, **kwargs: Any) -> dict[str, bytes]:
        return {
            "Signature": self.private_key.sign(
                kwargs["Message"],
                padding.PKCS1v15(),
                Prehashed(hashes.SHA256()),
            )
        }


class FakeHTTPClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> TWIHTTPResponse:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
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
    def handle(self, request: APIRequest) -> APIResponse:
        return APIResponse("success", {"delegated": request.operation})


class FakeApprovalVerifier:
    def require_approved_for(
        self,
        approval_id: Any,
        tenant_id: str,
        run_id: Any,
        action: str,
        resource: str,
        *,
        intent_fingerprint: str | None = None,
    ) -> None:
        raise AssertionError("search does not require human approval")


def test_platform_factory_routes_twi_through_policy_and_kms_signed_token() -> None:
    kms = FakeKMS()
    http = FakeHTTPClient()
    application = create_twi_platform_application(
        delegate=FakeDelegate(),
        approval_verifier=FakeApprovalVerifier(),
        environment="test",
        kms_client=kms,
        kms_key_id=KMS_KEY_ID,
        issuer=ISSUER,
        client_id="tinlyt-platform-service",
        twi_base_url="https://twi.internal",
        http_client=http,
    )
    principal = Principal(
        subject_id="agent-001",
        principal_type="agent",
        tenant_id="tenant-a",
        scopes=frozenset({"web.search"}),
    )
    response = application.api.dispatch(
        APIRequest(
            tenant_id="tenant-a",
            subject_id="agent-001",
            operation="twi.jobs.create_search",
            payload={"query": "agentic security", "limit": 5},
            request_id=str(uuid4()),
            idempotency_key="twi-search-000001",
            authenticated_principal=principal,
        )
    )

    assert response.status == "success"
    assert response.payload["job_id"] == "job-0000000000000001"
    assert len(http.calls) == 1
    assert http.calls[0]["url"] == "https://twi.internal/v1/jobs"
    assert json.loads(http.calls[0]["body"].decode("utf-8")) == {
        "kind": "search",
        "payload": {"query": "agentic security", "limit": 5},
    }
    bearer = http.calls[0]["headers"]["Authorization"]
    assert bearer.startswith("Bearer ")
    claims = jwt.decode(
        bearer.removeprefix("Bearer "),
        application.signer.public_key,
        algorithms=["RS256"],
        issuer=ISSUER,
        audience=AUDIENCE,
    )
    assert claims["tenant_id"] == "tenant-a"
    assert claims["sub"] == "agent-001"
    assert claims["principal_type"] == "agent"
    assert claims["scope"] == "twi:search"
    assert claims["client_id"] == "tinlyt-platform-service"
    assert application.jwks_provider.jwks()["keys"][0]["kid"] == KMS_KEY_ID
