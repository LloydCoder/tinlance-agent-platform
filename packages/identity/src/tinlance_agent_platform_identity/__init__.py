"""Identity boundary."""

from .cognito import create_cognito_access_token_verifier
from .federation import IdentityVerifier, VerifiedAgentIdentity, require_verified_identity
from .jwt_verifier import JWKSIdentityVerifier, SigningKeyProvider
from .resolver import (
    IdentityAuthenticationError,
    IdentityRevocationUnavailable,
    JWKSPrincipalResolver,
)
from .revocation import (
    DynamoDBTokenRevocationStore,
    SQLiteTokenRevocationStore,
    TokenRevocationChecker,
)
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
    "create_cognito_access_token_verifier",
    "SigningKeyProvider",
    "IdentityAuthenticationError",
    "IdentityRevocationUnavailable",
    "JWKSPrincipalResolver",
    "SQLiteTokenRevocationStore",
    "DynamoDBTokenRevocationStore",
    "TokenRevocationChecker",
    "KMSRS256Signer",
    "PlatformServiceTokenIssuer",
]
