from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from tinlance_agent_platform_identity.service_tokens import (
    KMSRS256Signer,
    PlatformServiceTokenIssuer,
)

ISSUER = "https://identity.tinlance.com/"
TWI_AUDIENCE = "https://api.tinlyt.tinlance.com"
WI_AUDIENCE = "world-intelligence"
KMS_KEY_ID = "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555"


class FakeKMS:
    def __init__(self) -> None:
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.sign_calls: list[dict[str, Any]] = []

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:
        assert KeyId == KMS_KEY_ID
        public_key = self.private_key.public_key()
        return {
            "KeyId": KMS_KEY_ID,
            "KeyUsage": "SIGN_VERIFY",
            "KeySpec": "RSA_2048",
            "SigningAlgorithms": ["RSASSA_PKCS1_V1_5_SHA_256"],
            "PublicKey": public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        }

    def sign(self, **kwargs: Any) -> dict[str, bytes]:
        self.sign_calls.append(kwargs)
        signature = self.private_key.sign(
            kwargs["Message"],
            padding.PKCS1v15(),
            Prehashed(hashes.SHA256()),
        )
        return {"Signature": signature}


@pytest.fixture
def configured_issuer() -> tuple[PlatformServiceTokenIssuer, FakeKMS, KMSRS256Signer]:
    kms = FakeKMS()
    signer = KMSRS256Signer(kms_client=kms, key_id=KMS_KEY_ID)
    issuer = PlatformServiceTokenIssuer(
        issuer=ISSUER,
        client_id="tinlyt-platform-service",
        allowed_audiences=frozenset({TWI_AUDIENCE, WI_AUDIENCE}),
        signer=signer,
    )
    return issuer, kms, signer


def test_issues_short_lived_rfc9068_style_twi_access_token(
    configured_issuer: tuple[PlatformServiceTokenIssuer, FakeKMS, KMSRS256Signer],
) -> None:
    issuer, kms, signer = configured_issuer
    token = issuer.issue_token(
        tenant_id="tenant-a",
        subject_id="user-a",
        audience=TWI_AUDIENCE,
        scopes=frozenset({"twi:search", "twi:fetch"}),
        request_id="request-123",
        traceparent=None,
        expires_in_seconds=60,
    )

    header = jwt.get_unverified_header(token)
    claims = jwt.decode(
        token,
        signer.public_key,
        algorithms=["RS256"],
        issuer=ISSUER,
        audience=TWI_AUDIENCE,
    )
    assert header == {"alg": "RS256", "kid": KMS_KEY_ID, "typ": "at+jwt"}
    assert claims["sub"] == "user-a"
    assert claims["tenant_id"] == "tenant-a"
    assert claims["principal_type"] == "user"
    assert claims["client_id"] == "tinlyt-platform-service"
    assert set(claims["scope"].split()) == {"twi:search", "twi:fetch"}
    assert claims["request_id"] == "request-123"
    assert 0 < claims["exp"] - claims["iat"] <= 60
    assert len(claims["jti"]) >= 32
    assert len(kms.sign_calls) == 1
    assert kms.sign_calls[0]["MessageType"] == "DIGEST"
    assert kms.sign_calls[0]["SigningAlgorithm"] == "RSASSA_PKCS1_V1_5_SHA_256"


def test_issues_purpose_bound_world_intelligence_token(
    configured_issuer: tuple[PlatformServiceTokenIssuer, FakeKMS, KMSRS256Signer],
) -> None:
    issuer, _, signer = configured_issuer
    token = issuer.issue_token(
        tenant_id="tenant-a",
        subject_id="agent-a",
        audience=WI_AUDIENCE,
        scopes=frozenset({"world-intelligence:query"}),
        purpose="competitive-monitoring",
        request_id="request-456",
        traceparent=None,
        expires_in_seconds=60,
    )
    claims = jwt.decode(token, signer.public_key, algorithms=["RS256"], audience=WI_AUDIENCE)
    assert claims["purpose"] == "competitive-monitoring"
    assert claims["scope"] == "world-intelligence:query"


def test_publishes_kms_public_key_as_jwks(
    configured_issuer: tuple[PlatformServiceTokenIssuer, FakeKMS, KMSRS256Signer],
) -> None:
    _, _, signer = configured_issuer
    jwks = signer.jwks()
    assert len(jwks["keys"]) == 1
    key = jwks["keys"][0]
    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert key["alg"] == "RS256"
    assert key["kid"] == KMS_KEY_ID
    modulus = int.from_bytes(base64.urlsafe_b64decode(key["n"] + "=="), "big")
    exponent = int.from_bytes(base64.urlsafe_b64decode(key["e"] + "=="), "big")
    numbers = signer.public_key.public_numbers()
    assert (modulus, exponent) == (numbers.n, numbers.e)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"tenant_id": " tenant-a", "subject_id": "user-a"},
        {"tenant_id": "tenant-a", "subject_id": " user-a"},
        {"tenant_id": "tenant-a", "subject_id": "user-a", "audience": "https://attacker.example"},
        {"tenant_id": "tenant-a", "subject_id": "user-a", "expires_in_seconds": 301},
        {"tenant_id": "tenant-a", "subject_id": "user-a", "scopes": frozenset()},
        {"tenant_id": "tenant-a", "subject_id": "user-a", "scopes": frozenset({" twi:search"})},
    ],
)
def test_rejects_invalid_or_untrusted_token_inputs(
    configured_issuer: tuple[PlatformServiceTokenIssuer, FakeKMS, KMSRS256Signer],
    kwargs: dict[str, Any],
) -> None:
    issuer, _, _ = configured_issuer
    values: dict[str, Any] = {
        "tenant_id": "tenant-a",
        "subject_id": "user-a",
        "audience": TWI_AUDIENCE,
        "scopes": frozenset({"twi:search"}),
        "request_id": "request-789",
        "traceparent": None,
        "expires_in_seconds": 60,
    }
    values.update(kwargs)
    with pytest.raises((ValueError, PermissionError)):
        issuer.issue_token(**values)


def test_rejects_non_signing_kms_keys() -> None:
    kms = FakeKMS()
    original = kms.get_public_key

    def wrong_usage(*, KeyId: str) -> dict[str, Any]:
        response = original(KeyId=KeyId)
        response["KeyUsage"] = "ENCRYPT_DECRYPT"
        return response

    kms.get_public_key = wrong_usage  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="SIGN_VERIFY"):
        KMSRS256Signer(kms_client=kms, key_id=KMS_KEY_ID)


def test_issuer_requires_https_and_explicit_audience_allowlist(
    configured_issuer: tuple[PlatformServiceTokenIssuer, FakeKMS, KMSRS256Signer],
) -> None:
    _, _, signer = configured_issuer
    with pytest.raises(ValueError, match="HTTPS"):
        PlatformServiceTokenIssuer(
            issuer="http://identity.tinlance.com",
            client_id="tinlyt-platform-service",
            allowed_audiences=frozenset({TWI_AUDIENCE}),
            signer=signer,
        )
    with pytest.raises(ValueError, match="audience"):
        PlatformServiceTokenIssuer(
            issuer=ISSUER,
            client_id="tinlyt-platform-service",
            allowed_audiences=frozenset(),
            signer=signer,
        )
