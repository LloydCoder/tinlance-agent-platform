from __future__ import annotations

from typing import Any
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from tinlance_agent_platform_api.service import APIRequest, APIResponse
from tinlance_agent_platform_app import create_extensions_platform_application
from tinlance_agent_platform_contracts import Principal
from tinlance_agent_platform_mcp.extensions import ExtensionsHTTPResponse

ISSUER = "https://platform.identity.tinlance.test/"
AUDIENCE = "tinlance-extensions-api"
KMS_KEY_ID = "arn:aws:kms:eu-west-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
JOB_ID = "a4f6d9e2-1c3b-4a5d-8e7f-9012bc345678"


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
    def __init__(self, response: ExtensionsHTTPResponse | None = None) -> None:
        self.response = response or ExtensionsHTTPResponse(
            200, {"content-type": "application/json"}, b'{"status":"cancelled"}'
        )
        self.calls: list[dict[str, Any]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> ExtensionsHTTPResponse:
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


class FakeDelegate:
    def handle(self, request: APIRequest) -> APIResponse:
        return APIResponse("success", {"delegated": request.operation})


def _application(http: FakeHTTPClient | None = None):
    return create_extensions_platform_application(
        delegate=FakeDelegate(),
        environment="test",
        kms_client=FakeKMS(),
        kms_key_id=KMS_KEY_ID,
        issuer=ISSUER,
        client_id="tinlance-extensions-platform",
        extensions_base_url="https://extensions.internal",
        http_client=http,
    )


def _principal(*scopes: str, tenant_id: str = "tenant-a") -> Principal:
    return Principal(
        subject_id="user-a",
        principal_type="user",
        tenant_id=tenant_id,
        scopes=frozenset(scopes),
    )


def test_job_cancellation_is_policy_checked_and_uses_platform_minted_scoped_token() -> None:
    http = FakeHTTPClient()
    application = _application(http)
    request_id = "platform-extensions-cancel-0001"
    response = application.api.dispatch(
        APIRequest(
            tenant_id="tenant-a",
            subject_id="user-a",
            operation="extensions.jobs.cancel",
            payload={"job_id": JOB_ID},
            request_id=request_id,
            authenticated_principal=_principal("extensions.jobs.cancel"),
        )
    )

    assert response.status == "success"
    assert response.payload == {"status": "cancelled"}
    assert len(http.calls) == 1
    call = http.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == f"https://extensions.internal/v1/jobs/{JOB_ID}/cancel"
    assert call["body"] is None
    assert call["headers"]["X-Request-ID"] == request_id
    bearer = call["headers"]["Authorization"]
    assert bearer.startswith("Bearer ")
    claims = jwt.decode(
        bearer.removeprefix("Bearer "),
        application.signer.public_key,
        algorithms=["RS256"],
        issuer=ISSUER,
        audience=AUDIENCE,
    )
    assert claims["tenant_id"] == "tenant-a"
    assert claims["sub"] == "user-a"
    assert claims["principal_type"] == "user"
    assert claims["scope"] == "extensions:jobs:cancel"
    assert claims["request_id"] == request_id
    assert claims["client_id"] == "tinlance-extensions-platform"


def test_job_cancellation_without_platform_capability_fails_before_network_call() -> None:
    http = FakeHTTPClient()
    application = _application(http)
    request = APIRequest(
        tenant_id="tenant-a",
        subject_id="user-a",
        operation="extensions.jobs.cancel",
        payload={"job_id": JOB_ID},
        request_id=str(uuid4()),
        authenticated_principal=_principal("extensions.jobs.read"),
    )
    try:
        application.api.dispatch(request)
    except PermissionError:
        pass
    else:
        raise AssertionError("missing Platform capability must be denied")
    assert http.calls == []


def test_tenant_or_subject_substitution_is_denied_before_transport() -> None:
    http = FakeHTTPClient()
    application = _application(http)
    request = APIRequest(
        tenant_id="tenant-b",
        subject_id="user-a",
        operation="extensions.jobs.cancel",
        payload={"job_id": JOB_ID},
        request_id=str(uuid4()),
        authenticated_principal=_principal("extensions.jobs.cancel"),
    )
    try:
        application.api.dispatch(request)
    except PermissionError:
        pass
    else:
        raise AssertionError("principal tenant mismatch must be denied")
    assert http.calls == []


def test_unregistered_platform_operations_are_delegated_unchanged() -> None:
    application = _application()
    response = application.api.dispatch(
        APIRequest(
            tenant_id="tenant-a",
            subject_id="user-a",
            operation="runs.read",
            payload={"run_id": "run-1"},
            request_id=str(uuid4()),
            authenticated_principal=_principal("extensions.jobs.cancel"),
        )
    )
    assert response.payload == {"delegated": "runs.read"}


def test_invalid_job_id_is_rejected_before_downstream_request() -> None:
    http = FakeHTTPClient()
    application = _application(http)
    request = APIRequest(
        tenant_id="tenant-a",
        subject_id="user-a",
        operation="extensions.jobs.cancel",
        payload={"job_id": "../../other-tenant"},
        request_id=str(uuid4()),
        authenticated_principal=_principal("extensions.jobs.cancel"),
    )
    try:
        application.api.dispatch(request)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid job identifier must be rejected")
    assert http.calls == []


def test_downstream_redirect_is_not_treated_as_success() -> None:
    http = FakeHTTPClient(ExtensionsHTTPResponse(302, {"location": "https://attacker.test"}, b""))
    application = _application(http)
    request = APIRequest(
        tenant_id="tenant-a",
        subject_id="user-a",
        operation="extensions.jobs.cancel",
        payload={"job_id": JOB_ID},
        request_id=str(uuid4()),
        authenticated_principal=_principal("extensions.jobs.cancel"),
    )
    response = application.api.dispatch(request)
    assert response.status == "failed"
    assert response.payload == {"error": "extensions_unavailable", "retryable": False}


def test_production_transport_rejects_plain_http() -> None:
    from tinlance_agent_platform_mcp.extensions import ExtensionsHTTPTransport

    class Issuer:
        def issue_token(self, **_kwargs: Any) -> str:
            return "opaque-token"

    try:
        ExtensionsHTTPTransport(base_url="http://extensions.internal", token_issuer=Issuer())
    except ValueError as exc:
        assert "plain HTTP" in str(exc)
    else:
        raise AssertionError("plain HTTP must be rejected by default")
