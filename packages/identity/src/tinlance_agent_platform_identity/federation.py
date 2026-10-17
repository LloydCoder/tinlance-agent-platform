"""Federated identity verification contracts for production adapters.

Cryptographic token verification belongs to the configured identity-provider
adapter. Only normalized, signature-verified claims may enter the authority
kernel; caller-supplied tenant and subject identifiers are never credentials.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol


@dataclass(frozen=True, slots=True)
class VerifiedAgentIdentity:
    subject_id: str
    tenant_id: str
    issuer: str
    audience: str
    scopes: frozenset[str]
    issued_at: datetime
    expires_at: datetime
    token_id: str
    nonce: str | None = None
    client_id: str | None = None
    principal_type: str = "federated"
    roles: frozenset[str] = frozenset()

    def validate(
        self,
        *,
        expected_issuer: str,
        expected_audience: str,
        now: datetime | None = None,
        expected_nonce: str | None = None,
    ) -> None:
        current = now or datetime.now(UTC)
        if self.issuer != expected_issuer or self.audience != expected_audience:
            raise PermissionError("identity issuer or audience is not trusted")
        if self.expires_at <= current or self.issued_at > current:
            raise PermissionError("identity assertion is outside its validity window")
        if self.expires_at <= self.issued_at:
            raise PermissionError("identity assertion has an invalid validity window")
        for value, name in (
            (self.subject_id, "subject"),
            (self.tenant_id, "tenant"),
            (self.token_id, "token identifier"),
            (self.principal_type, "principal type"),
        ):
            if not value or value != value.strip():
                raise PermissionError(f"identity {name} is incomplete or not normalized")
        if not self.client_id or self.client_id != self.client_id.strip():
            raise PermissionError("identity client_id is required and must be normalized")
        if any(not scope or scope != scope.strip() for scope in self.scopes):
            raise PermissionError("identity scopes must be normalized")
        if any(not role or role != role.strip() for role in self.roles):
            raise PermissionError("identity roles must be normalized")
        if expected_nonce is not None and self.nonce != expected_nonce:
            raise PermissionError("identity nonce does not match")


class IdentityVerifier(Protocol):
    def verify(
        self, assertion: str, *, expected_nonce: str | None = None
    ) -> VerifiedAgentIdentity: ...


def require_verified_identity(
    identity: VerifiedAgentIdentity,
    *,
    expected_issuer: str,
    expected_audience: str,
    now: datetime | None = None,
    expected_nonce: str | None = None,
) -> VerifiedAgentIdentity:
    identity.validate(
        expected_issuer=expected_issuer,
        expected_audience=expected_audience,
        now=now,
        expected_nonce=expected_nonce,
    )
    return identity
