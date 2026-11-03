"""Identity boundary."""

from .federation import IdentityVerifier, VerifiedAgentIdentity, require_verified_identity
from .jwt_verifier import JWKSIdentityVerifier, SigningKeyProvider
from .resolver import IdentityAuthenticationError, JWKSPrincipalResolver
from .revocation import SQLiteTokenRevocationStore, TokenRevocationChecker
from .service import validate_principal
from .service_tokens import KMSRS256Signer, PlatformServiceTokenIssuer
from .token_security import TokenSecurityContext

__all__ = [
    "IdentityVerifier",
    "VerifiedAgentIdentity",
    "require_verified_identity",
    "validate_principal",
    "TokenSecurityContext",
    "JWKSIdentityVerifier",
    "SigningKeyProvider",
    "IdentityAuthenticationError",
    "JWKSPrincipalResolver",
    "SQLiteTokenRevocationStore",
    "TokenRevocationChecker",
    "KMSRS256Signer",
    "PlatformServiceTokenIssuer",
]
