"""Resolver that binds verified JWT identity to the Platform principal contract."""

from __future__ import annotations

from dataclasses import dataclass

from tinlance_agent_platform_contracts import Principal

from .federation import IdentityVerifier
from .revocation import TokenRevocationChecker
from .service import validate_principal


class IdentityAuthenticationError(PermissionError):
    """Raised when identity verification or revocation checking cannot succeed."""


@dataclass(frozen=True, slots=True)
class JWKSPrincipalResolver:
    """Authenticate bearer tokens and fail closed on revocation-store failures."""

    verifier: IdentityVerifier
    revocation_checker: TokenRevocationChecker

    def resolve(self, bearer_token: str) -> Principal:
        try:
            identity = self.verifier.verify(bearer_token)
        except Exception as exc:
            raise IdentityAuthenticationError("identity assertion verification failed") from exc

        try:
            revoked = self.revocation_checker.is_revoked(identity.issuer, identity.token_id)
        except Exception as exc:
            raise IdentityAuthenticationError(
                "identity token revocation status is unavailable"
            ) from exc
        if revoked:
            raise IdentityAuthenticationError("identity token has been revoked")

        try:
            principal = Principal(
                subject_id=identity.subject_id,
                principal_type=identity.principal_type,
                tenant_id=identity.tenant_id,
                roles=identity.roles,
                scopes=identity.scopes,
            )
            return validate_principal(principal)
        except Exception as exc:
            raise IdentityAuthenticationError(
                "verified identity cannot form a valid principal"
            ) from exc
