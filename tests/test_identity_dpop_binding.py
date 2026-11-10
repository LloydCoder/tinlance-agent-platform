from __future__ import annotations

import base64
import hashlib
import json
import threading
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from tinlance_agent_platform_api.http import serve
from tinlance_agent_platform_api.service import AgentPlatformAPI, APIResponse
from tinlance_agent_platform_identity import (
    DPoPProofVerifier,
    JWKSIdentityVerifier,
    JWKSPrincipalResolver,
    SQLiteTokenRevocationStore,
)

ISSUER = "https://issuer.example.test/"
AUDIENCE = "tinlance-platform"
PUBLIC_ORIGIN = "https://api.example.test"
REQUEST_PATH = "/v1/agent-platform"


class StaticKeyProvider:
    def __init__(self, key: Any) -> None:
        self.key = key

    def get_signing_key_from_jwt(self, token: str) -> Any:
        return self.key


class ReplayCache:
    def __init__(self) -> None:
        self.seen: set[str] = set()

    def consume(self, jti: str, expires_at: datetime) -> bool:
        if jti in self.seen:
            return False
        self.seen.add(jti)
        return True


class EchoHandler:
    def handle(self, request: Any) -> APIResponse:
        return APIResponse("ok", {"tenant_id": request.tenant_id})


def make_binding_material() -> tuple[Any, Any, dict[str, str], str]:
    token_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    proof_key = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(proof_key.public_key()))
    thumbprint_members = {name: jwk[name] for name in ("crv", "kty", "x", "y")}
    canonical = json.dumps(
        thumbprint_members, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    thumbprint = (
        base64.urlsafe_b64encode(hashlib.sha256(canonical).digest())
        .decode("ascii")
        .rstrip("=")
    )
    return token_key, proof_key, jwk, thumbprint


def make_access_token(
    token_key: Any,
    thumbprint: str | None,
    *,
    cnf: object | None = None,
) -> str:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "iss": ISSUER,
        "sub": "subject-a",
        "aud": AUDIENCE,
        "jti": "access-jti-a",
        "client_id": "tinlance-test-client",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "tenant_id": "tenant-a",
        "principal_type": "user",
        "scope": "agent:run",
    }
    if cnf is not None:
        claims["cnf"] = cnf
    elif thumbprint is not None:
        claims["cnf"] = {"jkt": thumbprint}
    return jwt.encode(
        claims,
        token_key,
        algorithm="RS256",
        headers={"typ": "at+jwt", "kid": "key-1"},
    )


def make_dpop_proof(
    proof_key: Any,
    jwk: dict[str, str],
    access_token: str,
    *,
    uri: str = f"{PUBLIC_ORIGIN}{REQUEST_PATH}",
    jti: str = "proof-jti-a",
) -> str:
    now = datetime.now(UTC)
    ath = base64.urlsafe_b64encode(hashlib.sha256(access_token.encode()).digest()).decode(
        "ascii"
    ).rstrip("=")
    return jwt.encode(
        {
            "htm": "POST",
            "htu": uri,
            "iat": int(now.timestamp()),
            "jti": jti,
            "ath": ath,
        },
        proof_key,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )


def make_resolver(public_key: Any, database_path: Any) -> JWKSPrincipalResolver:
    verifier = JWKSIdentityVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url="https://issuer.example.test/.well-known/jwks.json",
        key_provider=StaticKeyProvider(public_key),
    )
    return JWKSPrincipalResolver(
        verifier,
        SQLiteTokenRevocationStore(database_path),
        dpop_verifier=DPoPProofVerifier(replay_cache=ReplayCache()),
    )


def send_request(
    endpoint: str, token: str, dpop_proof: str | None
) -> tuple[int, dict[str, object]]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Tinlance-API-Version": "1.1",
        "X-Request-ID": "dpop-request-001",
    }
    if dpop_proof is not None:
        headers["DPoP"] = dpop_proof
    request = urllib.request.Request(
        endpoint,
        data=json.dumps({"operation": "test.echo", "payload": {}}).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def with_server(resolver: JWKSPrincipalResolver):
    server = serve(
        AgentPlatformAPI(EchoHandler()),
        resolver,
        host="127.0.0.1",
        port=0,
        public_origin=PUBLIC_ORIGIN,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_address[1]}{REQUEST_PATH}"
    return server, thread, endpoint


def test_sender_bound_access_token_requires_a_matching_dpop_proof_over_http(tmp_path: Any) -> None:
    token_key, proof_key, jwk, thumbprint = make_binding_material()
    token = make_access_token(token_key, thumbprint)
    proof = make_dpop_proof(proof_key, jwk, token)
    public_key = token_key.public_key()
    resolver = make_resolver(public_key, tmp_path / "revocations.db")
    server, thread, endpoint = with_server(resolver)
    try:
        status, body = send_request(endpoint, token, proof)
        assert status == 200
        assert body["payload"] == {"tenant_id": "tenant-a"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_sender_bound_access_token_rejects_missing_dpop_proof_over_http(tmp_path: Any) -> None:
    token_key, _, _, thumbprint = make_binding_material()
    token = make_access_token(token_key, thumbprint)
    resolver = make_resolver(token_key.public_key(), tmp_path / "revocations.db")
    server, thread, endpoint = with_server(resolver)
    try:
        status, body = send_request(endpoint, token, None)
        assert status == 401
        assert body["error"] == "unauthorized"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_sender_bound_access_token_rejects_wrong_dpop_key_over_http(tmp_path: Any) -> None:
    token_key, _, _, thumbprint = make_binding_material()
    _, wrong_proof_key, wrong_jwk, _ = make_binding_material()
    token = make_access_token(token_key, thumbprint)
    proof = make_dpop_proof(wrong_proof_key, wrong_jwk, token)
    resolver = make_resolver(token_key.public_key(), tmp_path / "revocations.db")
    server, thread, endpoint = with_server(resolver)
    try:
        status, body = send_request(endpoint, token, proof)
        assert status == 401
        assert body["error"] == "unauthorized"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_sender_bound_access_token_rejects_dpop_uri_mismatch_over_http(tmp_path: Any) -> None:
    token_key, proof_key, jwk, thumbprint = make_binding_material()
    token = make_access_token(token_key, thumbprint)
    proof = make_dpop_proof(
        proof_key,
        jwk,
        token,
        uri=f"{PUBLIC_ORIGIN}/v1/other",
    )
    resolver = make_resolver(token_key.public_key(), tmp_path / "revocations.db")
    server, thread, endpoint = with_server(resolver)
    try:
        status, body = send_request(endpoint, token, proof)
        assert status == 401
        assert body["error"] == "unauthorized"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_bearer_token_rejects_unbound_dpop_proof_over_http(tmp_path: Any) -> None:
    token_key, proof_key, jwk, _ = make_binding_material()
    token = make_access_token(token_key, None)
    proof = make_dpop_proof(proof_key, jwk, token)
    resolver = make_resolver(token_key.public_key(), tmp_path / "revocations.db")
    server, thread, endpoint = with_server(resolver)
    try:
        status, body = send_request(endpoint, token, proof)
        assert status == 401
        assert body["error"] == "unauthorized"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_jwt_verifier_rejects_malformed_dpop_confirmation_claim() -> None:
    token_key, _, _, _ = make_binding_material()
    verifier = JWKSIdentityVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url="https://issuer.example.test/.well-known/jwks.json",
        key_provider=StaticKeyProvider(token_key.public_key()),
    )
    malformed = make_access_token(token_key, None, cnf={"jkt": "not-a-thumbprint"})
    with pytest.raises(PermissionError, match="confirmation"):
        verifier.verify(malformed)
