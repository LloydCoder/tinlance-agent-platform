"""Platform-owned short-lived service JWT issuance backed by AWS KMS asymmetric keys.

The KMS private key never leaves AWS. The signer publishes public JWK material only;
callers must still obtain scopes and tenant/subject context from Platform authorization.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any, Mapping, Protocol
from urllib.parse import urlsplit
from uuid import uuid4


_ALLOWED_PRINCIPAL_TYPES = frozenset({"user", "service", "agent", "workload"})
_ALLOWED_KMS_KEY_SPECS = frozenset({"RSA_2048", "RSA_3072", "RSA_4096"})
_KMS_SIGNING_ALGORITHM = "RSASSA_PKCS1_V1_5_SHA_256"
_TRACEPARENT_RE = re.compile(r"^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_SCOPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$")


class KMSClient(Protocol):
    """Minimal boto3-compatible AWS KMS client surface."""

    def get_public_key(self, *, KeyId: str) -> Mapping[str, Any]: ...

    def sign(
        self,
        *,
        KeyId: str,
        Message: bytes,
        MessageType: str,
        SigningAlgorithm: str,
    ) -> Mapping[str, Any]: ...


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unsigned_integer(value: int) -> bytes:
    if value < 1:
        raise ValueError("RSA public key integer must be positive")
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


class KMSRS256Signer:
    """RS256 JWS signer that delegates private-key operations to AWS KMS."""

    def __init__(
        self,
        *,
        kms_client: KMSClient,
        key_id: str,
        verification_key_ids: tuple[str, ...] = (),
    ) -> None:
        if not key_id or key_id != key_id.strip():
            raise ValueError("AWS KMS signing key identifier is required")
        requested_ids = (key_id, *verification_key_ids)
        if len(set(requested_ids)) != len(requested_ids) or any(
            not item or item != item.strip() for item in requested_ids
        ):
            raise ValueError("AWS KMS verification key identifiers must be unique and normalized")
        self._kms = kms_client
        self._public_keys: dict[str, Any] = {}
        for requested_id in requested_ids:
            response = kms_client.get_public_key(KeyId=requested_id)
            actual_id = response.get("KeyId")
            if not isinstance(actual_id, str) or not actual_id or actual_id != actual_id.strip():
                raise ValueError("AWS KMS did not return a valid key identifier")
            if response.get("KeyUsage") != "SIGN_VERIFY":
                raise ValueError("AWS KMS JWT key must have SIGN_VERIFY key usage")
            if response.get("KeySpec") not in _ALLOWED_KMS_KEY_SPECS:
                raise ValueError("AWS KMS JWT key must be an RSA asymmetric signing key")
            algorithms = response.get("SigningAlgorithms")
            if not isinstance(algorithms, list) or _KMS_SIGNING_ALGORITHM not in algorithms:
                raise ValueError("AWS KMS JWT key does not support RS256 signing")
            der = response.get("PublicKey")
            if not isinstance(der, bytes) or not der:
                raise ValueError("AWS KMS did not return public key material")
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

            try:
                public_key = serialization.load_der_public_key(der)
            except (TypeError, ValueError) as exc:
                raise ValueError("AWS KMS returned invalid DER public key material") from exc
            if not isinstance(public_key, RSAPublicKey):
                raise ValueError("AWS KMS JWT public key must be RSA")
            if actual_id in self._public_keys:
                raise ValueError("AWS KMS returned duplicate public key identifiers")
            self._public_keys[actual_id] = public_key
        self.key_id = next(iter(self._public_keys))

    @property
    def public_key(self) -> Any:
        """Return the active key's public half for local verification and tests."""
        return self._public_keys[self.key_id]

    def sign(self, signing_input: bytes) -> bytes:
        if not isinstance(signing_input, bytes) or not signing_input:
            raise ValueError("JWS signing input must be non-empty bytes")
        digest = hashlib.sha256(signing_input).digest()
        response = self._kms.sign(
            KeyId=self.key_id,
            Message=digest,
            MessageType="DIGEST",
            SigningAlgorithm=_KMS_SIGNING_ALGORITHM,
        )
        signature = response.get("Signature")
        if not isinstance(signature, bytes) or not signature:
            raise RuntimeError("AWS KMS returned an invalid JWT signature")
        return signature

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        """Return active and overlap public keys in RFC 7517 JWKS form."""
        keys: list[dict[str, str]] = []
        for key_id, public_key in self._public_keys.items():
            numbers = public_key.public_numbers()
            keys.append(
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": key_id,
                    "n": _b64url(_unsigned_integer(numbers.n)),
                    "e": _b64url(_unsigned_integer(numbers.e)),
                }
            )
        return {"keys": keys}


class PlatformServiceTokenIssuer:
    """Issue short-lived Platform access tokens for governed downstream services.

    The supplied tenant, subject and scopes must already be derived from a verified
    Platform principal and an authorization decision. This class signs claims; it
    does not authenticate callers or grant permissions.
    """

    def __init__(
        self,
        *,
        issuer: str,
        client_id: str,
        allowed_audiences: frozenset[str],
        signer: KMSRS256Signer,
    ) -> None:
        if not isinstance(issuer, str):
            raise ValueError("Platform service-token issuer must be a string")
        parsed = urlsplit(issuer)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Platform service-token issuer must be an HTTPS URL")
        if (
            not isinstance(client_id, str)
            or not client_id
            or client_id != client_id.strip()
            or not _IDENTIFIER_RE.fullmatch(client_id)
        ):
            raise ValueError("Platform service-token client identifier is invalid")
        if (
            not isinstance(allowed_audiences, frozenset)
            or not allowed_audiences
            or any(
                not isinstance(item, str) or not item or item != item.strip()
                for item in allowed_audiences
            )
        ):
            raise ValueError("an explicit normalized downstream audience allowlist is required")
        self._issuer = issuer
        self._client_id = client_id
        self._allowed_audiences = allowed_audiences
        self._signer = signer

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
        purpose: str | None = None,
        principal_type: str = "user",
    ) -> str:
        for value, name in (
            (tenant_id, "tenant identifier"),
            (subject_id, "subject identifier"),
            (request_id, "request identifier"),
        ):
            if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
                raise ValueError(f"Platform service-token {name} is invalid")
        if not isinstance(audience, str) or audience not in self._allowed_audiences:
            raise PermissionError("downstream token audience is not allowlisted")
        if (
            isinstance(expires_in_seconds, bool)
            or not isinstance(expires_in_seconds, int)
            or not 1 <= expires_in_seconds <= 300
        ):
            raise ValueError("downstream token lifetime must be between 1 and 300 seconds")
        if not isinstance(scopes, frozenset) or not scopes or any(
            not isinstance(scope, str) or not _SCOPE_RE.fullmatch(scope) for scope in scopes
        ):
            raise ValueError("downstream token scopes must be a non-empty set of normalized values")
        if (
            not isinstance(principal_type, str)
            or principal_type not in _ALLOWED_PRINCIPAL_TYPES
        ):
            raise ValueError("downstream token principal type is not supported")
        if purpose is not None and (
            not isinstance(purpose, str) or not _IDENTIFIER_RE.fullmatch(purpose)
        ):
            raise ValueError("downstream token purpose is invalid")
        if traceparent is not None and (
            not isinstance(traceparent, str)
            or not _TRACEPARENT_RE.fullmatch(traceparent)
            or traceparent[:2] == "ff"
            or traceparent[3:35] == "0" * 32
            or traceparent[36:52] == "0" * 16
        ):
            raise ValueError("downstream token traceparent is invalid")

        import time

        issued_at = int(time.time())
        claims: dict[str, object] = {
            "iss": self._issuer,
            "sub": subject_id,
            "aud": audience,
            "jti": uuid4().hex,
            "iat": issued_at,
            "exp": issued_at + expires_in_seconds,
            "tenant_id": tenant_id,
            "principal_type": principal_type,
            "client_id": self._client_id,
            "scope": " ".join(sorted(scopes)),
            "request_id": request_id,
        }
        if traceparent is not None:
            claims["traceparent"] = traceparent
        if purpose is not None:
            claims["purpose"] = purpose

        header = {"alg": "RS256", "kid": self._signer.key_id, "typ": "at+jwt"}
        encoded_header = _b64url(
            json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        encoded_claims = _b64url(
            json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
        signature = self._signer.sign(signing_input)
        return f"{encoded_header}.{encoded_claims}.{_b64url(signature)}"
