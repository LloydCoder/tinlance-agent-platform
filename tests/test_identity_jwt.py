from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from tinlance_agent_platform_identity import (
    JWKSIdentityVerifier,
    create_cognito_access_token_verifier,
)

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
        "client_id": "tinlance-test-client",
        "principal_type": "user",
        "roles": ["operator"],
        "scope": "agent:run evidence:read",
        "nonce": "nonce-123",
    }
    claims.update(overrides)
    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"typ": "at+jwt", "kid": "key-1"},
    )


def test_valid_jwks_identity_is_verified(verifier: tuple[JWKSIdentityVerifier, Any]) -> None:
    service, private_key = verifier
    identity = service.verify(make_token(private_key), expected_nonce="nonce-123")
    assert identity.subject_id == "user-123"
    assert identity.tenant_id == "tenant-123"
    assert identity.token_id == "token-123"
    assert identity.client_id == "tinlance-test-client"
    assert identity.principal_type == "user"
    assert identity.roles == frozenset({"operator"})
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
    service, _ = verifier
    token = jwt.encode(
        {"iss": ISSUER, "sub": "user-123", "aud": AUDIENCE},
        "not-a-public-key",
        algorithm="HS256",
        headers={"typ": "at+jwt"},
    )
    with pytest.raises(PermissionError, match="algorithm"):
        service.verify(token)


def test_missing_tenant_claim_is_rejected(verifier: tuple[JWKSIdentityVerifier, Any]) -> None:
    service, private_key = verifier
    with pytest.raises(PermissionError, match="tenant"):
        service.verify(make_token(private_key, tenant_id=None))


def test_https_configuration_is_mandatory() -> None:
    with pytest.raises(ValueError):
        JWKSIdentityVerifier(
            issuer="http://issuer.example.test",
            audience=AUDIENCE,
            jwks_url="https://issuer.example.test/keys",
        )
    with pytest.raises(ValueError):
        JWKSIdentityVerifier(
            issuer=ISSUER, audience=AUDIENCE, jwks_url="http://issuer.example.test/keys"
        )


def test_conflicting_tenant_aliases_are_rejected(
    verifier: tuple[JWKSIdentityVerifier, Any],
) -> None:
    service, private_key = verifier
    with pytest.raises(PermissionError, match="contradictory"):
        service.verify(make_token(private_key, tid="tenant-other"))


def test_client_id_and_principal_type_are_required(
    verifier: tuple[JWKSIdentityVerifier, Any],
) -> None:
    service, private_key = verifier
    with pytest.raises(PermissionError):
        service.verify(make_token(private_key, client_id=None))
    with pytest.raises(PermissionError, match="principal type"):
        service.verify(make_token(private_key, principal_type="superuser"))


def test_malformed_roles_and_conflicting_scope_claims_are_rejected(
    verifier: tuple[JWKSIdentityVerifier, Any],
) -> None:
    service, private_key = verifier
    with pytest.raises(PermissionError, match="roles"):
        service.verify(make_token(private_key, roles=["operator", " operator"]))
    with pytest.raises(PermissionError, match="contradictory"):
        service.verify(make_token(private_key, scp=["admin:all"]))


def test_future_not_before_and_extreme_numeric_dates_fail_closed(
    verifier: tuple[JWKSIdentityVerifier, Any],
) -> None:
    service, private_key = verifier
    with pytest.raises(PermissionError):
        service.verify(
            make_token(
                private_key,
                nbf=int((datetime.now(UTC) + timedelta(minutes=10)).timestamp()),
            )
        )
    with pytest.raises(PermissionError):
        service.verify(make_token(private_key, iat=-1e100))


def test_jwks_key_id_and_clock_leeway_are_validated(
    verifier: tuple[JWKSIdentityVerifier, Any],
) -> None:
    service, private_key = verifier
    token = jwt.encode(
        {
            "iss": ISSUER,
            "sub": "user-123",
            "aud": AUDIENCE,
            "jti": "token-123",
            "client_id": "tinlance-test-client",
            "iat": int(datetime.now(UTC).timestamp()),
            "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
            "tenant_id": "tenant-123",
            "principal_type": "user",
        },
        private_key,
        algorithm="RS256",
        headers={"typ": "at+jwt"},
    )
    with pytest.raises(PermissionError, match="key identifier"):
        service.verify(token)
    with pytest.raises(ValueError, match="leeway"):
        JWKSIdentityVerifier(
            issuer=ISSUER,
            audience=AUDIENCE,
            jwks_url="https://issuer.example.test/.well-known/jwks.json",
            leeway_seconds=-1,
        )
    with pytest.raises(ValueError, match="timeout"):
        JWKSIdentityVerifier(
            issuer=ISSUER,
            audience=AUDIENCE,
            jwks_url="https://issuer.example.test/.well-known/jwks.json",
            jwks_timeout_seconds=float("inf"),
        )


def test_clock_leeway_is_applied_consistently_to_expiry(
    verifier: tuple[JWKSIdentityVerifier, Any],
) -> None:
    service, private_key = verifier
    now = datetime.now(UTC)
    issued_at = int((now - timedelta(minutes=3)).timestamp())
    within_leeway = make_token(
        private_key,
        iat=issued_at,
        exp=int((now - timedelta(seconds=30)).timestamp()),
    )
    identity = service.verify(within_leeway)
    assert identity.token_id == "token-123"

    outside_leeway = make_token(
        private_key,
        iat=issued_at,
        exp=int((now - timedelta(seconds=90)).timestamp()),
    )
    with pytest.raises(PermissionError):
        service.verify(outside_leeway)


def make_cognito_token(private_key: Any, **overrides: Any) -> str:
    now = datetime.now(UTC)
    claims = {
        "iss": "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_Abc123",
        "sub": "cognito-user-123",
        "aud": "https://api.tinlyt.tinlance.com",
        "jti": "cognito-token-123",
        "origin_jti": "cognito-session-123",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "tenant_id": "tenant-123",
        "client_id": "tinlytwebclient123",
        "token_use": "access",
        "principal_type": "user",
        "cognito:groups": ["operator"],
        "scope": "openid profile tinlyt/web.search tinlyt/web.fetch",
    }
    omit_origin_jti = overrides.pop("_omit_origin_jti", False)
    claims.update(overrides)
    if omit_origin_jti:
        claims.pop("origin_jti", None)
    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"kid": "cognito-key"},
    )


def test_cognito_access_token_profile_verifies_resource_bound_user_access_token() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = create_cognito_access_token_verifier(
        region="eu-west-1",
        user_pool_id="eu-west-1_Abc123",
        audience="https://api.tinlyt.tinlance.com",
        client_ids=("tinlytwebclient123",),
        key_provider=StaticKeyProvider(private_key.public_key()),
    )
    identity = verifier.verify(make_cognito_token(private_key))
    assert identity.subject_id == "cognito-user-123"
    assert identity.tenant_id == "tenant-123"
    assert identity.client_id == "tinlytwebclient123"
    assert identity.principal_type == "user"
    assert identity.roles == frozenset({"operator"})
    assert identity.scopes == frozenset({"web.search", "web.fetch"})
    assert identity.revocation_ids == frozenset({"cognito-session-123"})


def test_cognito_profile_rejects_id_tokens_and_unapproved_app_clients() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = create_cognito_access_token_verifier(
        region="eu-west-1",
        user_pool_id="eu-west-1_Abc123",
        audience="https://api.tinlyt.tinlance.com",
        client_ids=("tinlytwebclient123",),
        key_provider=StaticKeyProvider(private_key.public_key()),
    )
    with pytest.raises(PermissionError, match="token use"):
        verifier.verify(make_cognito_token(private_key, token_use="id"))
    with pytest.raises(PermissionError, match="client identifier"):
        verifier.verify(make_cognito_token(private_key, client_id="otherclient123"))


def test_cognito_profile_requires_resource_audience_and_exact_user_pool_region() -> None:
    with pytest.raises(ValueError, match="region"):
        create_cognito_access_token_verifier(
            region="invalid-region",
            user_pool_id="invalid-region_Abc123",
            audience="https://api.tinlyt.tinlance.com",
            client_ids=("tinlytwebclient123",),
        )
    with pytest.raises(ValueError, match="user pool"):
        create_cognito_access_token_verifier(
            region="eu-west-1",
            user_pool_id="us-east-1_Abc123",
            audience="https://api.tinlyt.tinlance.com",
            client_ids=("tinlytwebclient123",),
        )
    with pytest.raises(ValueError, match="HTTPS resource"):
        create_cognito_access_token_verifier(
            region="eu-west-1",
            user_pool_id="eu-west-1_Abc123",
            audience="http://api.tinlyt.tinlance.com",
            client_ids=("tinlytwebclient123",),
        )
    with pytest.raises(ValueError, match="client"):
        create_cognito_access_token_verifier(
            region="eu-west-1",
            user_pool_id="eu-west-1_Abc123",
            audience="https://api.tinlyt.tinlance.com",
            client_ids=(),
        )


def test_cognito_profile_rejects_malformed_origin_jti() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = create_cognito_access_token_verifier(
        region="eu-west-1",
        user_pool_id="eu-west-1_Abc123",
        audience="https://api.tinlyt.tinlance.com",
        client_ids=("tinlytwebclient123",),
        key_provider=StaticKeyProvider(private_key.public_key()),
    )
    with pytest.raises(PermissionError, match="origin_jti"):
        verifier.verify(make_cognito_token(private_key, origin_jti=""))
    with pytest.raises(PermissionError, match="origin_jti"):
        verifier.verify(make_cognito_token(private_key, origin_jti=123))
    with pytest.raises(PermissionError, match="verification failed"):
        verifier.verify(make_cognito_token(private_key, _omit_origin_jti=True))


def test_cognito_profile_normalizes_only_the_configured_resource_server_scopes() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = create_cognito_access_token_verifier(
        region="eu-west-1",
        user_pool_id="eu-west-1_Abc123",
        audience="https://api.tinlyt.tinlance.com",
        client_ids=("tinlytwebclient123",),
        key_provider=StaticKeyProvider(private_key.public_key()),
    )
    identity = verifier.verify(make_cognito_token(private_key))
    assert identity.scopes == frozenset({"web.search", "web.fetch"})


def test_cognito_profile_rejects_unprefixed_or_foreign_resource_scopes() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = create_cognito_access_token_verifier(
        region="eu-west-1",
        user_pool_id="eu-west-1_Abc123",
        audience="https://api.tinlyt.tinlance.com",
        client_ids=("tinlytwebclient123",),
        key_provider=StaticKeyProvider(private_key.public_key()),
    )
    with pytest.raises(PermissionError, match="scope"):
        verifier.verify(make_cognito_token(private_key, scope="openid web.search"))
    with pytest.raises(PermissionError, match="scope"):
        verifier.verify(make_cognito_token(private_key, scope="openid other-api/web.search"))
