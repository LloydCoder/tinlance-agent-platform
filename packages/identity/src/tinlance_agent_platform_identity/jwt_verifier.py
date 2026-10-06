"""Cryptographic JWT/JWKS identity verification for production adapters."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

import jwt
from jwt import PyJWKClient

from .federation import VerifiedAgentIdentity


class SigningKeyProvider(Protocol):
    def get_signing_key_from_jwt(self, token: str) -> Any: ...


@dataclass(frozen=True, slots=True)
class JWKSIdentityVerifier:
    issuer: str
    audience: str
    jwks_url: str
    algorithms: tuple[str, ...] = ("RS256", "ES256", "EdDSA")
    leeway_seconds: int = 60
    expected_typ: str | None = None
    tenant_claims: tuple[str, ...] = ("tenant_id", "tid")
    key_provider: SigningKeyProvider | None = None

    def __post_init__(self) -> None:
        if not self.issuer.startswith("https://"):
            raise ValueError("identity issuer must use HTTPS")
        if not self.jwks_url.startswith("https://"):
            raise ValueError("JWKS endpoint must use HTTPS")
        if not self.audience.strip():
            raise ValueError("identity audience is required")
        if not self.algorithms or any(
            algorithm not in {"RS256", "PS256", "ES256", "EdDSA"} for algorithm in self.algorithms
        ):
            raise ValueError("identity algorithms are not allowed")

    def _provider(self) -> SigningKeyProvider:
        if self.key_provider is not None:
            return self.key_provider
        return PyJWKClient(self.jwks_url, cache_jwk_set=True, lifespan=300)

    def verify(self, assertion: str, *, expected_nonce: str | None = None) -> VerifiedAgentIdentity:
        if not assertion or any(character.isspace() for character in assertion):
            raise PermissionError("identity assertion is malformed")
        try:
            header = jwt.get_unverified_header(assertion)
            if self.expected_typ is not None and header.get("typ") != self.expected_typ:
                raise PermissionError("identity token type is not trusted")
            if header.get("alg") not in self.algorithms:
                raise PermissionError("identity token algorithm is not trusted")
            signing_key = self._provider().get_signing_key_from_jwt(assertion)
            claims = jwt.decode(
                assertion,
                signing_key,
                algorithms=list(self.algorithms),
                issuer=self.issuer,
                audience=self.audience,
                leeway=self.leeway_seconds,
                options={"require": ["exp", "iat", "iss", "sub", "jti"]},
            )
        except PermissionError:
            raise
        except Exception as exc:
            raise PermissionError("identity assertion verification failed") from exc

        subject = self._required_string(claims, "sub")
        token_id = self._required_string(claims, "jti")
        tenant_id = self._tenant_id(claims)
        issued_at = self._timestamp(claims, "iat")
        expires_at = self._timestamp(claims, "exp")
        nonce = claims.get("nonce")
        if expected_nonce is not None and nonce != expected_nonce:
            raise PermissionError("identity token nonce does not match")
        scopes = self._scopes(claims)
        identity = VerifiedAgentIdentity(
            subject_id=subject,
            tenant_id=tenant_id,
            issuer=self.issuer,
            audience=self.audience,
            scopes=frozenset(scopes),
            issued_at=issued_at,
            expires_at=expires_at,
            token_id=token_id,
            nonce=str(nonce) if nonce is not None else None,
        )
        identity.validate(
            expected_issuer=self.issuer,
            expected_audience=self.audience,
            now=datetime.now(UTC),
            expected_nonce=expected_nonce,
        )
        return identity

    @staticmethod
    def _required_string(claims: dict[str, Any], name: str) -> str:
        value = claims.get(name)
        if not isinstance(value, str) or not value.strip():
            raise PermissionError(f"identity claim {name!r} is required")
        return value

    def _tenant_id(self, claims: dict[str, Any]) -> str:
        for name in self.tenant_claims:
            value = claims.get(name)
            if isinstance(value, str) and value.strip():
                return value
        raise PermissionError("identity tenant claim is required")

    @staticmethod
    def _timestamp(claims: dict[str, Any], name: str) -> datetime:
        value = claims.get(name)
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise PermissionError(f"identity claim {name!r} must be NumericDate")
        return datetime.fromtimestamp(value, UTC)

    @staticmethod
    def _scopes(claims: dict[str, Any]) -> tuple[str, ...]:
        value = claims.get("scope", claims.get("scp", ""))
        if isinstance(value, str):
            return tuple(item for item in value.split() if item)
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            return tuple(item for item in value if item)
        raise PermissionError("identity scopes are malformed")
