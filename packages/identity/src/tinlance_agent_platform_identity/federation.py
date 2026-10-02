"""Federated identity verification contracts for production adapters.

Cryptographic token verification belongs to the configured identity provider
adapter. This module validates the normalized claims that the authority kernel
is allowed to consume after verification.
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

    def validate(
        self,
        *,
        expected_issuer: str,
        expected_audience: str,
        now: datetime | None = None,
    ) -> None:
        current = now or datetime.now(UTC)
        if self.issuer != expected_issuer or self.audience != expected_audience:
            raise PermissionError("identity issuer or audience is not trusted")
        if self.expires_at <= current or self.issued_at > current:
            raise PermissionError("identity assertion is outside its validity window")
        if not self.subject_id or not self.tenant_id or not self.token_id:
            raise PermissionError("identity assertion is incomplete")
        if any(not scope or scope != scope.strip() for scope in self.scopes):
            raise PermissionError("identity scopes must be normalized")


class IdentityVerifier(Protocol):
    def verify(self, assertion: str) -> VerifiedAgentIdentity: ...


def require_verified_identity(
    identity: VerifiedAgentIdentity,
    *,
    expected_issuer: str,
    expected_audience: str,
    now: datetime | None = None,
) -> VerifiedAgentIdentity:
    identity.validate(expected_issuer=expected_issuer, expected_audience=expected_audience, now=now)
    return identity
