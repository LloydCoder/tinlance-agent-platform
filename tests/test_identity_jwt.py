from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from tinlance_agent_platform_identity import JWKSIdentityVerifier

ISSUER = "https://issuer.example.test/"
AUDIENCE = "tinlance-platform"


class StaticKeyProvider:
    def __init__(self, key: Any) -> None:
        self.key = key

    def get_signing_key_from_jwt(self, token: str) -> Any:
        return self.key


@pytest.fixture
def verifier() -> tuple[JWKSIdentityVerifier, Any]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = JWKSIdentityVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url="https://issuer.example.test/.well-known/jwks.json",
        expected_typ="at+jwt",
        key_provider=StaticKeyProvider(private_key.public_key()),
    )
    return verifier, private_key


def make_token(private_key: Any, **overrides: Any) -> str:
    now = datetime.now(UTC)
    claims = {
        "iss": ISSUER,
        "sub": "user-123",
        "aud": AUDIENCE,
        "jti": "token-123",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "tenant_id": "tenant-123",
        "scope": "agent:run evidence:read",
        "nonce": "nonce-123",
    }
    claims.update(overrides)
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"typ": "at+jwt"})


def test_valid_jwks_identity_is_verified(verifier: tuple[JWKSIdentityVerifier, Any]) -> None:
    service, private_key = verifier
    identity = service.verify(make_token(private_key), expected_nonce="nonce-123")
    assert identity.subject_id == "user-123"
    assert identity.tenant_id == "tenant-123"
    assert identity.token_id == "token-123"
    assert identity.scopes == frozenset({"agent:run", "evidence:read"})


def test_wrong_issuer_is_rejected(verifier: tuple[JWKSIdentityVerifier, Any]) -> None:
    service, private_key = verifier
    with pytest.raises(PermissionError):
        service.verify(make_token(private_key, iss="https://attacker.example.test/"))


def test_wrong_audience_is_rejected(verifier: tuple[JWKSIdentityVerifier, Any]) -> None:
    service, private_key = verifier
    with pytest.raises(PermissionError):
        service.verify(make_token(private_key, aud="other-service"))


def test_expired_token_is_rejected(verifier: tuple[JWKSIdentityVerifier, Any]) -> None:
    service, private_key = verifier
    expired = datetime.now(UTC) - timedelta(minutes=10)
    with pytest.raises(PermissionError):
        service.verify(
            make_token(
                private_key,
                iat=int((expired - timedelta(minutes=1)).timestamp()),
                exp=int(expired.timestamp()),
            )
        )


def test_nonce_mismatch_is_rejected(verifier: tuple[JWKSIdentityVerifier, Any]) -> None:
    service, private_key = verifier
    with pytest.raises(PermissionError, match="nonce"):
        service.verify(make_token(private_key), expected_nonce="wrong")


def test_wrong_algorithm_is_rejected(verifier: tuple[JWKSIdentityVerifier, Any]) -> None:
    service, private_key = verifier
    token = jwt.encode(
        {"iss": ISSUER, "sub": "user-123", "aud": AUDIENCE},
        private_key,
        algorithm="RS256",
        headers={"typ": "JWT"},
    )
    with pytest.raises(PermissionError, match="type"):
        service.verify(token)


def test_https_configuration_is_mandatory() -> None:
    with pytest.raises(ValueError):
        JWKSIdentityVerifier(issuer="http://issuer.example.test", audience=AUDIENCE, jwks_url="https://issuer.example.test/keys")
    with pytest.raises(ValueError):
        JWKSIdentityVerifier(issuer=ISSUER, audience=AUDIENCE, jwks_url="http://issuer.example.test/keys")