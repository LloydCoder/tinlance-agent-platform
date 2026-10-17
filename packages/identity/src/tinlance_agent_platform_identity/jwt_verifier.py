"""Strict JWT/JWKS verification for federated Platform principals.

The verifier accepts only explicitly configured HTTPS issuers, audiences,
algorithms, token types and tenant claim names. It does not grant permissions;
the Platform authorization and policy layers remain authoritative.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import urlsplit

import jwt
from jwt import PyJWKClient

from .federation import VerifiedAgentIdentity

_ALLOWED_ALGORITHMS = frozenset({"RS256", "PS256", "ES256", "EdDSA"})
_DEFAULT_PRINCIPAL_TYPES = frozenset({"user", "service", "agent", "workload"})


class SigningKeyProvider(Protocol):
    def get_signing_key_from_jwt(self, token: str) -> Any: ...


@dataclass(frozen=True, slots=True)
class JWKSIdentityVerifier:
    issuer: str
    audience: str
    jwks_url: str
    algorithms: tuple[str, ...] = ("RS256", "ES256", "EdDSA")
    leeway_seconds: int = 60
    expected_typ: str | None = "at+jwt"
    tenant_claims: tuple[str, ...] = ("tenant_id", "tid")
    principal_type_claim: str = "principal_type"
    roles_claim: str = "roles"
    allowed_principal_types: frozenset[str] = _DEFAULT_PRINCIPAL_TYPES
    require_client_id: bool = True
    require_kid: bool = True
    jwks_timeout_seconds: float = 5.0
    key_provider: SigningKeyProvider | None = None

    def __post_init__(self) -> None:
        issuer = urlsplit(self.issuer)
        jwks = urlsplit(self.jwks_url)
        if (
            issuer.scheme != "https"
            or not issuer.hostname
            or issuer.username is not None
            or issuer.password is not None
            or issuer.fragment
        ):
            raise ValueError("identity issuer must be a valid HTTPS URL")
        if (
            jwks.scheme != "https"
            or not jwks.hostname
            or jwks.username is not None
            or jwks.password is not None
            or jwks.fragment
        ):
            raise ValueError("JWKS endpoint must be a valid HTTPS URL")
        if not self.audience or self.audience != self.audience.strip():
            raise ValueError("identity audience is required and must be normalized")
        if (
            not self.algorithms
            or len(set(self.algorithms)) != len(self.algorithms)
            or any(algorithm not in _ALLOWED_ALGORITHMS for algorithm in self.algorithms)
        ):
            raise ValueError("identity algorithms are not allowed")
        if (
            isinstance(self.leeway_seconds, bool)
            or not isinstance(self.leeway_seconds, int)
            or not 0 <= self.leeway_seconds <= 300
        ):
            raise ValueError("identity clock leeway must be an integer between 0 and 300 seconds")
        if (
            isinstance(self.jwks_timeout_seconds, bool)
            or not isinstance(self.jwks_timeout_seconds, (int, float))
            or not math.isfinite(self.jwks_timeout_seconds)
            or self.jwks_timeout_seconds <= 0
        ):
            raise ValueError("JWKS timeout must be a finite positive number")
        if self.expected_typ is not None and (
            not self.expected_typ or self.expected_typ != self.expected_typ.strip()
        ):
            raise ValueError("expected token type must be normalized when configured")
        if not isinstance(self.require_client_id, bool) or not isinstance(self.require_kid, bool):
            raise ValueError("JWT strictness options must be boolean")
        if (
            not self.tenant_claims
            or len(set(self.tenant_claims)) != len(self.tenant_claims)
            or any(not name or name != name.strip() for name in self.tenant_claims)
        ):
            raise ValueError("tenant claim names must be non-empty and unique")
        if (
            not self.principal_type_claim
            or self.principal_type_claim != self.principal_type_claim.strip()
            or not self.allowed_principal_types
            or any(not item or item != item.strip() for item in self.allowed_principal_types)
        ):
            raise ValueError("principal type claim and allowlist must be configured")

    def _provider(self) -> SigningKeyProvider:
        if self.key_provider is not None:
            return self.key_provider
        return PyJWKClient(
            self.jwks_url,
            cache_jwk_set=True,
            lifespan=300,
            timeout=self.jwks_timeout_seconds,
        )

    def verify(
        self, assertion: str, *, expected_nonce: str | None = None
    ) -> VerifiedAgentIdentity:
        if not isinstance(assertion, str) or not assertion or any(
            character.isspace() for character in assertion
        ):
            raise PermissionError("identity assertion is malformed")
        try:
            header = jwt.get_unverified_header(assertion)
            if self.expected_typ is not None:
                actual_typ = header.get("typ")
                if not isinstance(actual_typ, str) or actual_typ.lower() != self.expected_typ.lower():
                    raise PermissionError("identity token type is not trusted")
            if header.get("alg") not in self.algorithms:
                raise PermissionError("identity token algorithm is not trusted")
            key_id = header.get("kid")
            if self.require_kid and (
                not isinstance(key_id, str) or not key_id or key_id != key_id.strip()
            ):
                raise PermissionError("identity token key identifier is required")
            signing_key = self._provider().get_signing_key_from_jwt(assertion)
            required = ["exp", "iat", "iss", "sub", "jti"]
            if self.require_client_id:
                required.append("client_id")
            claims = jwt.decode(
                assertion,
                signing_key,
                algorithms=list(self.algorithms),
                issuer=self.issuer,
                audience=self.audience,
                leeway=self.leeway_seconds,
                options={"require": required},
            )
        except PermissionError:
            raise
        except Exception as exc:
            raise PermissionError("identity assertion verification failed") from exc

        subject = self._required_string(claims, "sub")
        token_id = self._required_string(claims, "jti")
        tenant_id = self._tenant_id(claims)
        principal_type = self._required_string(claims, self.principal_type_claim)
        if principal_type not in self.allowed_principal_types:
            raise PermissionError("identity principal type is not trusted")
        client_id_value = claims.get("client_id")
        client_id = (
            self._required_string(claims, "client_id")
            if client_id_value is not None or self.require_client_id
            else None
        )
        issued_at = self._timestamp(claims, "iat")
        expires_at = self._timestamp(claims, "exp")
        nonce_value = claims.get("nonce")
        if nonce_value is not None and (
            not isinstance(nonce_value, str) or nonce_value != nonce_value.strip()
        ):
            raise PermissionError("identity nonce is malformed")
        if expected_nonce is not None and nonce_value != expected_nonce:
            raise PermissionError("identity token nonce does not match")
        scopes = frozenset(self._scopes(claims))
        roles = frozenset(self._roles(claims))
        identity = VerifiedAgentIdentity(
            subject_id=subject,
            tenant_id=tenant_id,
            issuer=self.issuer,
            audience=self.audience,
            scopes=scopes,
            issued_at=issued_at,
            expires_at=expires_at,
            token_id=token_id,
            nonce=nonce_value,
            client_id=client_id,
            principal_type=principal_type,
            roles=roles,
        )
        identity.validate(
            expected_issuer=self.issuer,
            expected_audience=self.audience,
            now=datetime.now(UTC),
            expected_nonce=expected_nonce,
            leeway_seconds=self.leeway_seconds,
        )
        return identity

    @staticmethod
    def _required_string(claims: dict[str, Any], name: str) -> str:
        value = claims.get(name)
        if not isinstance(value, str) or not value or value != value.strip():
            raise PermissionError(f"identity claim {name!r} is required and must be normalized")
        if any(ord(character) < 0x21 or ord(character) == 0x7F for character in value):
            raise PermissionError(f"identity claim {name!r} contains invalid characters")
        return value

    def _tenant_id(self, claims: dict[str, Any]) -> str:
        values: list[str] = []
        for name in self.tenant_claims:
            if name not in claims:
                continue
            value = claims[name]
            if not isinstance(value, str) or not value or value != value.strip():
                raise PermissionError(f"identity tenant claim {name!r} is malformed")
            values.append(value)
        if not values:
            raise PermissionError("identity tenant claim is required")
        if len(set(values)) != 1:
            raise PermissionError("identity tenant claims are contradictory")
        return values[0]

    @staticmethod
    def _timestamp(claims: dict[str, Any], name: str) -> datetime:
        value = claims.get(name)
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise PermissionError(f"identity claim {name!r} must be NumericDate")
        try:
            return datetime.fromtimestamp(value, UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise PermissionError(f"identity claim {name!r} is outside the supported range") from exc

    @staticmethod
    def _scopes(claims: dict[str, Any]) -> tuple[str, ...]:
        def parse(value: object, name: str) -> tuple[str, ...]:
            if isinstance(value, str):
                items = tuple(value.split())
            elif isinstance(value, list) and all(isinstance(item, str) for item in value):
                items = tuple(value)
            else:
                raise PermissionError(f"identity scope claim {name!r} is malformed")
            if any(not item or item != item.strip() for item in items):
                raise PermissionError("identity scopes must be normalized")
            return tuple(sorted(set(items)))

        values = [parse(claims[name], name) for name in ("scope", "scp") if name in claims]
        if not values:
            return ()
        if any(value != values[0] for value in values[1:]):
            raise PermissionError("identity scope claims are contradictory")
        return values[0]

    def _roles(self, claims: dict[str, Any]) -> tuple[str, ...]:
        value = claims.get(self.roles_claim, [])
        if not isinstance(value, list) or any(
            not isinstance(item, str) or not item or item != item.strip() for item in value
        ):
            raise PermissionError("identity roles claim is malformed")
        return tuple(sorted(set(value)))
