from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from tinlance_agent_platform_identity.dpop import DPoPProofVerifier


class ReplayCache:
    def __init__(self) -> None:
        self.seen: set[str] = set()

    def consume(self, jti: str, expires_at: datetime) -> bool:
        if jti in self.seen:
            return False
        self.seen.add(jti)
        return True


@pytest.fixture
def proof_context() -> tuple[DPoPProofVerifier, Any, ReplayCache]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key()))
    cache = ReplayCache()
    return DPoPProofVerifier(replay_cache=cache), (private_key, public_jwk), cache


def make_proof(
    private_key: Any,
    public_jwk: dict[str, str],
    *,
    method: str = "POST",
    uri: str = "https://api.example.test/v1/agents?debug=1",
    access_token: str = "access-token",
    now: datetime | None = None,
    jti: str = "proof-123",
    headers: dict[str, object] | None = None,
    claims: dict[str, object] | None = None,
) -> str:
    current = now or datetime.now(UTC)
    payload: dict[str, object] = {
        "htm": method,
        "htu": "https://api.example.test/v1/agents",
        "iat": int(current.timestamp()),
        "jti": jti,
        "ath": base64.urlsafe_b64encode(hashlib.sha256(access_token.encode()).digest())
        .decode("ascii")
        .rstrip("="),
    }
    payload.update(claims or {})
    token_headers: dict[str, object] = {"typ": "dpop+jwt", "jwk": public_jwk}
    token_headers.update(headers or {})
    return jwt.encode(payload, private_key, algorithm="ES256", headers=token_headers)


def test_dpop_proof_verifies_signature_request_binding_and_access_token_hash(
    proof_context: tuple[DPoPProofVerifier, Any, ReplayCache],
) -> None:
    verifier, (private_key, public_jwk), _ = proof_context
    proof = make_proof(private_key, public_jwk)

    result = verifier.verify(
        proof,
        method="POST",
        uri="https://api.example.test/v1/agents?debug=1",
        access_token="access-token",
    )

    assert result.jti == "proof-123"
    assert result.jwk_thumbprint
    assert len(result.jwk_thumbprint) == 43


@pytest.mark.parametrize(
    ("method", "uri", "access_token", "claims"),
    [
        ("GET", "https://api.example.test/v1/agents?debug=1", "access-token", {}),
        ("POST", "https://api.example.test/v1/other", "access-token", {}),
        ("POST", "https://api.example.test/v1/agents?debug=1", "other-token", {}),
        ("POST", "https://api.example.test/v1/agents?debug=1", "access-token", {"htm": "GET"}),
    ],
)
def test_dpop_proof_rejects_request_or_token_binding_mismatch(
    proof_context: tuple[DPoPProofVerifier, Any, ReplayCache],
    method: str,
    uri: str,
    access_token: str,
    claims: dict[str, object],
) -> None:
    verifier, (private_key, public_jwk), _ = proof_context
    proof = make_proof(private_key, public_jwk, claims=claims)

    with pytest.raises(PermissionError):
        verifier.verify(proof, method=method, uri=uri, access_token=access_token)


def test_dpop_proof_rejects_replay(
    proof_context: tuple[DPoPProofVerifier, Any, ReplayCache],
) -> None:
    verifier, (private_key, public_jwk), _ = proof_context
    proof = make_proof(private_key, public_jwk)
    verifier.verify(
        proof,
        method="POST",
        uri="https://api.example.test/v1/agents?debug=1",
        access_token="access-token",
    )

    with pytest.raises(PermissionError, match="replay"):
        verifier.verify(
            proof,
            method="POST",
            uri="https://api.example.test/v1/agents?debug=1",
            access_token="access-token",
        )


def test_dpop_proof_rejects_stale_and_future_issued_at(
    proof_context: tuple[DPoPProofVerifier, Any, ReplayCache],
) -> None:
    verifier, (private_key, public_jwk), _ = proof_context
    now = datetime.now(UTC)
    for issued_at in (now - timedelta(minutes=10), now + timedelta(minutes=2)):
        proof = make_proof(private_key, public_jwk, now=issued_at, jti=str(issued_at.timestamp()))
        with pytest.raises(PermissionError, match="freshness"):
            verifier.verify(
                proof,
                method="POST",
                uri="https://api.example.test/v1/agents?debug=1",
                access_token="access-token",
                now=now,
            )


def test_dpop_proof_rejects_private_jwk_material(
    proof_context: tuple[DPoPProofVerifier, Any, ReplayCache],
) -> None:
    verifier, (private_key, public_jwk), _ = proof_context
    proof = make_proof(
        private_key,
        public_jwk,
        headers={"jwk": {**public_jwk, "d": "private-material"}},
    )

    with pytest.raises(PermissionError, match="public"):
        verifier.verify(
            proof,
            method="POST",
            uri="https://api.example.test/v1/agents?debug=1",
            access_token="access-token",
        )


def test_dpop_proof_rejects_token_controlled_key_locations(
    proof_context: tuple[DPoPProofVerifier, Any, ReplayCache],
) -> None:
    verifier, (private_key, public_jwk), _ = proof_context
    proof = make_proof(
        private_key,
        public_jwk,
        headers={"jku": "https://attacker.example.test/jwks.json"},
    )

    with pytest.raises(PermissionError):
        verifier.verify(
            proof,
            method="POST",
            uri="https://api.example.test/v1/agents?debug=1",
            access_token="access-token",
        )


def test_dpop_proof_rejects_non_ascii_access_token_hash_suffix(
    proof_context: tuple[DPoPProofVerifier, Any, ReplayCache],
) -> None:
    verifier, (private_key, public_jwk), _ = proof_context
    expected_ath = base64.urlsafe_b64encode(
        hashlib.sha256(b"access-token").digest()
    ).decode("ascii").rstrip("=")
    proof = make_proof(
        private_key,
        public_jwk,
        claims={"ath": expected_ath + "é"},
    )

    with pytest.raises(PermissionError, match="hash"):
        verifier.verify(
            proof,
            method="POST",
            uri="https://api.example.test/v1/agents?debug=1",
            access_token="access-token",
        )
