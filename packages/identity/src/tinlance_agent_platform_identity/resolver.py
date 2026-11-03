"""Resolver that binds verified JWT identity to the Platform principal contract."""

from __future__ import annotations

from dataclasses import dataclass

from tinlance_agent_platform_contracts import PlatformAuthenticationFailure, Principal

from .federation import IdentityVerifier
from .revocation import TokenRevocationChecker
from .service import validate_principal


class IdentityAuthenticationError(PlatformAuthenticationFailure):
    """Raised when identity verification or revocation checking cannot succeed."""


class IdentityRevocationUnavailable(RuntimeError):
    """Raised when the authenticated identity cannot be durably revoked."""


@dataclass(frozen=True, slots=True)
class JWKSPrincipalResolver:
    """Authenticate bearer tokens and fail closed on revocation-store failures."""

    verifier: IdentityVerifier
    revocation_checker: TokenRevocationChecker

    def revoke_session(self, bearer_token: str) -> None:
        """Revoke the verified access token and its configured token-family IDs.

        This method intentionally does not reject an already-revoked token so
        sign-out retries remain idempotent.
        """

        try:
            identity = self.verifier.verify(bearer_token)
        except Exception as exc:
            raise IdentityAuthenticationError("identity assertion verification failed") from exc
        writer = getattr(self.revocation_checker, "revoke_identity", None)
        if not callable(writer):
            raise IdentityRevocationUnavailable(
                "identity revocation storage does not support durable writes"
            )
        try:
            writer(identity, reason="user_sign_out")
        except Exception as exc:
            raise IdentityRevocationUnavailable(
                "identity revocation could not be persisted"
            ) from exc

    def resolve(self, bearer_token: str) -> Principal:
        try:
            identity = self.verifier.verify(bearer_token)
        except Exception as exc:
            raise IdentityAuthenticationError("identity assertion verification failed") from exc

        revocation_ids = sorted({identity.token_id, *identity.revocation_ids})
        for revocation_id in revocation_ids:
            try:
                revoked = self.revocation_checker.is_revoked(identity.issuer, revocation_id)
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
