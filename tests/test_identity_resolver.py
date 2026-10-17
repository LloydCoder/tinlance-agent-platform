from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from datetime import UTC, timedelta
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from tinlance_agent_platform_api.http import serve
from tinlance_agent_platform_api.service import APIRequest, APIResponse, AgentPlatformAPI
from tinlance_agent_platform_identity import (
    IdentityAuthenticationError,
    JWKSIdentityVerifier,
    JWKSPrincipalResolver,
    SQLiteTokenRevocationStore,
    TokenRevocationChecker,
)

ISSUER = "https://issuer.example.test/"
AUDIENCE = "tinlance-platform"


class StaticKeyProvider:
    def __init__(self, key: Any) -> None:
        self.key = key

    def get_signing_key_from_jwt(self, token: str) -> Any:
        return self.key


class EchoHandler:
    def __init__(self) -> None:
        self.requests: list[APIRequest] = []

    def handle(self, request: APIRequest) -> APIResponse:
        self.requests.append(request)
        return APIResponse(
            "ok",
            {
                "tenant_id": getattr(request, "tenant_id"),
                "subject_id": getattr(request, "subject_id"),
            },
        )


class UnavailableRevocationStore:
    def is_revoked(self, issuer: str, token_id: str) -> bool:
        raise OSError("revocation backend unavailable")


@pytest.fixture
def signing_material() -> tuple[Any, Any]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def make_token(private_key: Any, **overrides: Any) -> str:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "iss": ISSUER,
        "sub": "subject-a",
        "aud": AUDIENCE,
        "jti": "jti-a",
        "client_id": "tinlance-test-client",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "tenant_id": "tenant-a",
        "principal_type": "user",
        "roles": ["operator"],
        "scope": "agent:run evidence:read",
    }
    claims.update(overrides)
    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"typ": "at+jwt", "kid": "key-1"},
    )


def resolver_for(
    public_key: Any,
    revocations: TokenRevocationChecker,
) -> JWKSPrincipalResolver:
    verifier = JWKSIdentityVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url="https://issuer.example.test/.well-known/jwks.json",
        key_provider=StaticKeyProvider(public_key),
    )
    return JWKSPrincipalResolver(verifier, revocations)


def send_request(
    endpoint: str,
    token: str,
    *,
    tenant_id: str = "tenant-a",
    subject_id: str = "subject-a",
) -> tuple[int, dict[str, object]]:
    body = json.dumps(
        {
            "tenant_id": tenant_id,
            "subject_id": subject_id,
            "operation": "test.echo",
            "payload": {},
        }
    ).encode()
    request = urllib.request.Request(
        endpoint,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-Tinlance-API-Version": "1.1",
            "X-Request-ID": "request-identity-001",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def with_server(resolver: JWKSPrincipalResolver):
    handler = EchoHandler()
    server = serve(AgentPlatformAPI(handler), resolver, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_address[1]}/v1/agent-platform"
    return handler, server, thread, endpoint


def test_resolver_maps_verified_identity_to_platform_principal(
    signing_material: tuple[Any, Any], tmp_path: Path
) -> None:
    private_key, public_key = signing_material
    revocations = SQLiteTokenRevocationStore(tmp_path / "revocations.db")
    resolver = resolver_for(public_key, revocations)
    principal = resolver.resolve(make_token(private_key))
    assert principal.subject_id == "subject-a"
    assert principal.tenant_id == "tenant-a"
    assert principal.principal_type == "user"
    assert principal.roles == frozenset({"operator"})
    assert principal.scopes == frozenset({"agent:run", "evidence:read"})


def test_http_boundary_binds_request_tenant_to_verified_identity(
    signing_material: tuple[Any, Any], tmp_path: Path
) -> None:
    private_key, public_key = signing_material
    resolver = resolver_for(public_key, SQLiteTokenRevocationStore(tmp_path / "revocations.db"))
    handler, server, thread, endpoint = with_server(resolver)
    try:
        status, body = send_request(endpoint, make_token(private_key))
        assert status == 200
        assert body["payload"] == {"tenant_id": "tenant-a", "subject_id": "subject-a"}
        assert len(handler.requests) == 1

        status, body = send_request(endpoint, make_token(private_key), tenant_id="tenant-victim")
        assert status == 403
        assert body["error"] == "forbidden"
        assert len(handler.requests) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_revoked_tokens_are_rejected_and_store_survives_restart(
    signing_material: tuple[Any, Any], tmp_path: Path
) -> None:
    private_key, public_key = signing_material
    path = tmp_path / "revocations.db"
    first_store = SQLiteTokenRevocationStore(path)
    assert first_store.revoke(ISSUER, "jti-a", reason="security incident")
    assert not first_store.revoke(ISSUER, "jti-a", reason="duplicate")
    second_store = SQLiteTokenRevocationStore(path)
    assert second_store.is_revoked(ISSUER, "jti-a")
    assert not second_store.is_revoked("https://other-issuer.example/", "jti-a")

    resolver = resolver_for(public_key, second_store)
    handler, server, thread, endpoint = with_server(resolver)
    try:
        status, body = send_request(endpoint, make_token(private_key))
        assert status == 401
        assert body["error"] == "unauthorized"
        assert handler.requests == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_revocation_backend_failure_fails_closed(
    signing_material: tuple[Any, Any], tmp_path: Path
) -> None:
    private_key, public_key = signing_material
    resolver = resolver_for(public_key, UnavailableRevocationStore())
    handler, server, thread, endpoint = with_server(resolver)
    try:
        status, body = send_request(endpoint, make_token(private_key))
        assert status == 401
        assert body["error"] == "unauthorized"
        assert handler.requests == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_identity_resolver_rejects_invalid_signature(
    signing_material: tuple[Any, Any], tmp_path: Path
) -> None:
    _, public_key = signing_material
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    resolver = resolver_for(public_key, SQLiteTokenRevocationStore(tmp_path / "revocations.db"))
    with pytest.raises(IdentityAuthenticationError):
        resolver.resolve(make_token(attacker_key))
