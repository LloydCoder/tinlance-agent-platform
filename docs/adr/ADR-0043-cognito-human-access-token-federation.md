# ADR-0043: Cognito human access-token federation for Tinlyt

- Status: Proposed
- Date: 2026-11-03
- Decision owners: Tinlance Agent Platform

## Context

The Platform needs a human sign-in provider for the Tinlyt browser application. The existing
Platform service-token issuer is strictly downstream: it signs short-lived Platform-to-TWI tokens
after the caller has already been authenticated and authorized. It is not an inbound identity
provider.

The Platform already has a provider-neutral JWKSIdentityVerifier and JWKSPrincipalResolver.
Amazon Cognito user pools can issue RS256 access tokens through managed login's OAuth authorization-
code flow. Cognito resource binding adds an aud claim identifying the API resource, while the
access token also contains client_id and token_use=access.

## Decision

Provide a strict create_cognito_access_token_verifier profile around the existing verifier.
The profile fixes:

- Exact regional Cognito issuer derived from the configured Region and user-pool ID.
- The pool's HTTPS JWKS endpoint and RS256 only.
- An exact HTTPS resource audience supplied by the OAuth resource parameter.
- An explicit allowlist of Cognito app-client IDs, validated against the access token's client_id.
- token_use=access; ID tokens are never accepted as API bearer tokens.
- A required server-issued tenant_id claim and principal_type=user.
- cognito:groups as descriptive roles only; groups do not bypass Platform authorization or policy.

Cognito access tokens do not use the Platform's private typ=at+jwt convention. This provider
profile therefore does not require a typ header; it compensates with the cryptographically
verified Cognito issuer, RS256/JWKS, resource-bound audience, client allowlist and mandatory
token_use=access claim. The generic verifier's default strict typ=at+jwt behavior is unchanged
for Platform-issued service tokens and other providers.

## Required Cognito configuration

1. Use a dedicated Tinlyt user pool in the selected AWS Region. Do not reuse the ThreatFade
   Keycloak realm or another product's identity tenant.
2. Use Cognito managed login with authorization-code grant and PKCE S256. Do not enable implicit
   grant or a client secret in the browser application.
3. Configure the app client with only the required callback/logout URLs, scopes and authorization
   code grant.
4. Configure the OAuth resource identifier as the exact HTTPS Platform API resource, for example
   https://api.tinlyt.tinlance.com. The browser must request that exact resource parameter and
   the Platform verifier must validate the resulting aud against the same exact string.
5. Configure a Pre Token Generation V2 trigger to add tenant_id and the constant
   principal_type=user to access tokens. The trigger must derive tenant membership from a
   server-controlled membership source keyed by the authenticated Cognito sub. It must not
   trust browser input, OAuth clientMetadata, mutable user attributes, email domains, or
   caller-supplied tenant claims.
6. Restrict membership writes to an administrative control plane. User-facing app clients must
   not be able to change tenant membership or the principal type.
7. The app client ID allowlist in the Platform deployment must match the intended production
   app client exactly. Preview/staging clients should use separate explicit configuration.

## Tenant model for initial rollout

The first release supports one active tenant mapping per Cognito subject. A user with no active
membership is denied token issuance. A user with conflicting or malformed membership data is
denied. Multi-tenant account switching requires a separate server-authorized tenant-selection
flow and must not be implemented by trusting a browser-supplied tenant_id.

The Pre Token Generation Lambda must fail closed if its membership lookup is unavailable, returns
no active tenant, or returns an invalid tenant identifier. It must not cache membership decisions
across invocations in a way that survives revocation or membership changes.

## Security and operations

- The browser is a public OAuth client: authorization code + PKCE S256, exact redirect URI
  allowlist, unpredictable state, OIDC nonce where applicable, and no embedded client secret.
- The Platform API accepts access tokens only. It must reject ID tokens, tokens from other pools,
  other app clients, other resource audiences, expired tokens, malformed claims and unknown keys.
- Tenant and subject are taken exclusively from the verified token principal. Browser JSON fields
  for tenant/subject remain ignored or rejected by the Platform API handler.
- Group claims are metadata; Platform policy remains authoritative for capabilities, approvals,
  budgets and consequential actions.
- JWKS retrieval uses HTTPS, bounded timeouts and the existing key cache. Unknown kid, malformed
  JWKS and provider outages fail closed.
- Logs must not contain bearer tokens, authorization codes, PKCE verifiers or refresh tokens.
- Configure alarms for Lambda errors/throttles, Cognito sign-in failures and API authorization
  denials. Define membership revocation and account-disable procedures before beta.
- Do not create AWS resources until the current credit balance, expected monthly spend and a
  least-privilege deployment role have been verified.

## Consequences

The profile is provider-specific configuration, not a second authorization system. The Platform
still resolves the verified identity into its principal model and applies tenant membership,
authorization, policy, approval and audit controls. This code and ADR do not create a user pool,
domain, app client, Lambda trigger, membership table, DNS record or production API.

## References

- Cognito access-token claims: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html
- Cognito resource binding: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-define-resource-servers.html
- Cognito authorization endpoint: https://docs.aws.amazon.com/cognito/latest/developerguide/authorization-endpoint.html
- Cognito Pre Token Generation trigger: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html
- Cognito user-pool security best practices: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-security-best-practices.html
- RFC 8707: https://www.rfc-editor.org/rfc/rfc8707.html
