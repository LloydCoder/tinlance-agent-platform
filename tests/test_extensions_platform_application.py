from __future__ import annotations

from typing import Any
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from tinlance_agent_platform_api.service import APIRequest, APIResponse
from tinlance_agent_platform_app import (
    compute_extensions_dead_letter_replay_intent_fingerprint,
    create_extensions_platform_application,
    extensions_dead_letter_replay_run_id,
)
from tinlance_agent_platform_approvals import ApprovalService
from tinlance_agent_platform_contracts import ApprovalStatus, Principal
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


def _application(
    http: FakeHTTPClient | None = None,
    approval_verifier: ApprovalService | None = None,
):
    return create_extensions_platform_application(
        delegate=FakeDelegate(),
        environment="test",
        kms_client=FakeKMS(),
        kms_key_id=KMS_KEY_ID,
        issuer=ISSUER,
        client_id="tinlance-extensions-platform",
        extensions_base_url="https://extensions.internal",
        http_client=http,
        approval_verifier=approval_verifier,
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


# fmt: off
EVENT_ID = "c4f6d9e2-1c3b-4a5d-8e7f-9012bc345679"
REPLAY_IDEMPOTENCY_KEY = "replay-idempotency-0001"


def _approved_replay_request(approval_service: ApprovalService, request_id: str):
    run_id = extensions_dead_letter_replay_run_id(
        tenant_id="tenant-a",
        subject_id="user-a",
        request_id=request_id,
    )
    arguments = {
        "event_id": EVENT_ID,
        "idempotency_key": REPLAY_IDEMPOTENCY_KEY,
    }
    fingerprint = compute_extensions_dead_letter_replay_intent_fingerprint(
        tenant_id="tenant-a",
        subject_id="user-a",
        run_id=str(run_id),
        arguments=arguments,
    )
    approval = approval_service.request(
        "tenant-a",
        run_id,
        "replay",
        "extensions://outbox/dead-letters/{event_id}",
        "Replay a previously dead-lettered Extensions event",
        "user-a",
        intent_fingerprint=fingerprint,
    )
    approval_service.decide(
        approval.approval_id,
        True,
        "tenant-a",
        approver_subject_id="approver-b",
        intent_fingerprint=fingerprint,
    )
    return run_id, fingerprint, approval.approval_id, {
        **arguments,
        "run_id": str(run_id),
        "approval_id": str(approval.approval_id),
        "intent_fingerprint": fingerprint,
    }


def test_dead_letter_replay_requires_bound_human_approval_and_scoped_token() -> None:
    http = FakeHTTPClient(
        ExtensionsHTTPResponse(
            200,
            {"content-type": "application/json"},
            b'{"status":"requeued"}',
        )
    )
    approvals = ApprovalService()
    request_id = "platform-extensions-replay-0001"
    run_id, fingerprint, approval_id, payload = _approved_replay_request(approvals, request_id)
    application = _application(http, approval_verifier=approvals)
    response = application.api.dispatch(
        APIRequest(
            tenant_id="tenant-a",
            subject_id="user-a",
            operation="extensions.outbox.dead_letter.replay",
            payload=payload,
            request_id=request_id,
            idempotency_key=REPLAY_IDEMPOTENCY_KEY,
            authenticated_principal=_principal("extensions.outbox.dead_letter.replay"),
        )
    )

    assert response.status == "success"
    assert response.payload == {"status": "requeued"}
    assert len(http.calls) == 1
    call = http.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == (
        f"https://extensions.internal/v1/outbox/dead-letters/{EVENT_ID}/replay"
    )
    assert call["body"] is None
    assert call["headers"]["X-Request-ID"] == request_id
    assert call["headers"]["Idempotency-Key"] == REPLAY_IDEMPOTENCY_KEY
    token = call["headers"]["Authorization"].removeprefix("Bearer ")
    claims = jwt.decode(
        token,
        application.signer.public_key,
        algorithms=["RS256"],
        issuer=ISSUER,
        audience=AUDIENCE,
    )
    assert claims["tenant_id"] == "tenant-a"
    assert claims["sub"] == "user-a"
    assert claims["scope"] == "extensions:outbox:replay"
    assert claims["request_id"] == request_id
    assert str(run_id) == payload["run_id"]
    assert fingerprint == payload["intent_fingerprint"]
    assert approvals.get(approval_id, "tenant-a").status is ApprovalStatus.CONSUMED


def test_dead_letter_replay_fails_closed_without_approval_verifier() -> None:
    http = FakeHTTPClient()
    approvals = ApprovalService()
    request_id = "platform-extensions-replay-0002"
    _run_id, _fingerprint, _approval_id, payload = _approved_replay_request(approvals, request_id)
    application = _application(http)
    request = APIRequest(
        tenant_id="tenant-a",
        subject_id="user-a",
        operation="extensions.outbox.dead_letter.replay",
        payload=payload,
        request_id=request_id,
        idempotency_key=REPLAY_IDEMPOTENCY_KEY,
        authenticated_principal=_principal("extensions.outbox.dead_letter.replay"),
    )
    try:
        application.api.dispatch(request)
    except PermissionError:
        pass
    else:
        raise AssertionError(
            "dead-letter replay must fail closed without an approval verifier"
        )
    assert http.calls == []


def test_dead_letter_replay_rejects_approval_for_different_event_intent() -> None:
    http = FakeHTTPClient()
    approvals = ApprovalService()
    request_id = "platform-extensions-replay-0003"
    _run_id, _fingerprint, _approval_id, payload = _approved_replay_request(approvals, request_id)
    payload["event_id"] = "d4f6d9e2-1c3b-4a5d-8e7f-9012bc345670"
    application = _application(http, approval_verifier=approvals)
    request = APIRequest(
        tenant_id="tenant-a",
        subject_id="user-a",
        operation="extensions.outbox.dead_letter.replay",
        payload=payload,
        request_id=request_id,
        idempotency_key=REPLAY_IDEMPOTENCY_KEY,
        authenticated_principal=_principal("extensions.outbox.dead_letter.replay"),
    )
    try:
        application.api.dispatch(request)
    except PermissionError:
        pass
    else:
        raise AssertionError("approval must be bound to the exact event and intent")
    assert http.calls == []
# fmt: on
