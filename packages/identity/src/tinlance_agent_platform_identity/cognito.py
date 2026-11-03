"""Strict Amazon Cognito user-pool access-token verifier profile.

This factory configures the provider-neutral JWKS verifier for human-user access
tokens issued through Cognito managed login with OAuth resource binding.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from .jwt_verifier import JWKSIdentityVerifier, SigningKeyProvider
from .resolver import JWKSPrincipalResolver
from .revocation import TokenRevocationChecker

_REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]+$")
_POOL_SUFFIX = re.compile(r"^[A-Za-z0-9]+$")
_CLAIM_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_:-]{0,63}$")
_CLIENT_ID = re.compile(r"^[A-Za-z0-9]{1,128}$")


def create_cognito_access_token_verifier(
    *,
    region: str,
    user_pool_id: str,
    audience: str,
    client_ids: tuple[str, ...],
    tenant_claim: str = "tenant_id",
    jwks_timeout_seconds: float = 5.0,
    key_provider: SigningKeyProvider | None = None,
) -> JWKSIdentityVerifier:
    """Build a verifier that accepts only resource-bound Cognito user access tokens.

    The configured audience must match the OAuth `resource` parameter used by
    the frontend authorization-code flow. The Pre Token Generation V2 trigger
    must add a trusted `tenant_id` claim and a constant `principal_type=user`.
    """

    if not isinstance(region, str) or not _REGION.fullmatch(region):
        raise ValueError("Cognito region is invalid")
    if (
        not isinstance(user_pool_id, str)
        or not user_pool_id.startswith(f"{region}_")
        or not _POOL_SUFFIX.fullmatch(user_pool_id[len(region) + 1 :])
    ):
        raise ValueError("Cognito user pool ID must belong to the configured region")
    resource = urlsplit(audience)
    if (
        resource.scheme != "https"
        or not resource.hostname
        or resource.username is not None
        or resource.password is not None
        or resource.fragment
    ):
        raise ValueError("Cognito audience must be an HTTPS resource identifier")
    if (
        not isinstance(client_ids, tuple)
        or not client_ids
        or len(set(client_ids)) != len(client_ids)
        or any(
            not isinstance(client_id, str) or not _CLIENT_ID.fullmatch(client_id)
            for client_id in client_ids
        )
    ):
        raise ValueError("Cognito app client allowlist must contain unique valid client IDs")
    if not isinstance(tenant_claim, str) or not _CLAIM_NAME.fullmatch(tenant_claim):
        raise ValueError("Cognito tenant claim name is invalid")

    issuer = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"
    return JWKSIdentityVerifier(
        issuer=issuer,
        audience=audience,
        jwks_url=f"{issuer}/.well-known/jwks.json",
        algorithms=("RS256",),
        expected_typ=None,
        tenant_claims=(tenant_claim,),
        principal_type_claim="principal_type",
        roles_claim="cognito:groups",
        require_client_id=True,
        require_kid=True,
        expected_token_use="access",
        allowed_client_ids=frozenset(client_ids),
        jwks_timeout_seconds=jwks_timeout_seconds,
        key_provider=key_provider,
    )



def create_cognito_principal_resolver(
    *,
    revocation_checker: TokenRevocationChecker,
    region: str,
    user_pool_id: str,
    audience: str,
    client_ids: tuple[str, ...],
    tenant_claim: str = "tenant_id",
    jwks_timeout_seconds: float = 5.0,
    key_provider: SigningKeyProvider | None = None,
) -> JWKSPrincipalResolver:
    """Compose Cognito access-token verification with fail-closed revocation checks."""

    verifier = create_cognito_access_token_verifier(
        region=region,
        user_pool_id=user_pool_id,
        audience=audience,
        client_ids=client_ids,
        tenant_claim=tenant_claim,
        jwks_timeout_seconds=jwks_timeout_seconds,
        key_provider=key_provider,
    )
    return JWKSPrincipalResolver(verifier=verifier, revocation_checker=revocation_checker)
