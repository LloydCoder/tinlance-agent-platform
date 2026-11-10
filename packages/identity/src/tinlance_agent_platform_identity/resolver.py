"""Resolver that binds verified JWT identity to the Platform principal contract."""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from tinlance_agent_platform_contracts import PlatformAuthenticationFailure, Principal

from .dpop import DPoPProofVerifier
from .federation import IdentityVerifier, VerifiedAgentIdentity
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
    dpop_verifier: DPoPProofVerifier | None = None

    def revoke_session(
        self,
        bearer_token: str,
        *,
        request_id: str,
        dpop_proof: str | None = None,
        method: str | None = None,
        uri: str | None = None,
    ) -> None:
        """Revoke the verified access token and its configured token-family IDs.

        This method intentionally does not reject an already-revoked token so
        sign-out retries remain idempotent.
        """
        try:
            identity = self.verifier.verify(bearer_token)
        except Exception as exc:
            raise IdentityAuthenticationError("identity assertion verification failed") from exc
        self._verify_dpop_binding(
            identity,
            access_token=bearer_token,
            dpop_proof=dpop_proof,
            method=method,
            uri=uri,
        )
        writer = getattr(self.revocation_checker, "revoke_identity", None)
        if not callable(writer):
            raise IdentityRevocationUnavailable(
                "identity revocation storage does not support durable writes"
            )
        try:
            writer(identity, reason="user_sign_out", request_id=request_id)
        except Exception as exc:
            raise IdentityRevocationUnavailable(
                "identity revocation could not be persisted"
            ) from exc

    def resolve(self, bearer_token: str) -> Principal:
        return self._resolve(bearer_token)

    def resolve_with_dpop(
        self,
        bearer_token: str,
        dpop_proof: str,
        *,
        method: str,
        uri: str,
    ) -> Principal:
        return self._resolve(bearer_token, dpop_proof=dpop_proof, method=method, uri=uri)

    def _resolve(
        self,
        bearer_token: str,
        *,
        dpop_proof: str | None = None,
        method: str | None = None,
        uri: str | None = None,
    ) -> Principal:
        try:
            identity = self.verifier.verify(bearer_token)
        except Exception as exc:
            raise IdentityAuthenticationError("identity assertion verification failed") from exc
        self._verify_dpop_binding(
            identity,
            access_token=bearer_token,
            dpop_proof=dpop_proof,
            method=method,
            uri=uri,
        )

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

    def _verify_dpop_binding(
        self,
        identity: VerifiedAgentIdentity,
        *,
        access_token: str,
        dpop_proof: str | None,
        method: str | None,
        uri: str | None,
    ) -> None:
        expected_thumbprint = identity.sender_key_thumbprint
        if expected_thumbprint is None:
            if dpop_proof is not None:
                raise IdentityAuthenticationError(
                    "DPoP proof cannot be used with an unbound bearer token"
                )
            return
        if self.dpop_verifier is None or dpop_proof is None or method is None or uri is None:
            raise IdentityAuthenticationError(
                "sender-constrained access token requires a DPoP proof"
            )
        try:
            verified = self.dpop_verifier.verify(
                dpop_proof,
                method=method,
                uri=uri,
                access_token=access_token,
            )
        except Exception as exc:
            raise IdentityAuthenticationError("DPoP proof verification failed") from exc
        if not hmac.compare_digest(
            verified.jwk_thumbprint.encode("ascii"),
            expected_thumbprint.encode("ascii"),
        ):
            raise IdentityAuthenticationError("DPoP proof key does not match access-token binding")
