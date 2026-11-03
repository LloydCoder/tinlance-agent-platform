# Amazon Cognito access-token profile for Tinlyt

## Purpose

Use a dedicated Cognito user pool as Tinlyt's inbound human identity provider. The Platform API accepts only Cognito **access tokens** that are signed by the configured pool, bound to the Tinlyt API resource, issued to an allowlisted app client, and carry trusted tenant and principal claims.

The implementation is provider-neutral at the HTTP boundary. Configure `JWKSPrincipalResolver` with `create_cognito_access_token_verifier(...)` and a production revocation checker.

## Required Cognito configuration

- User pool feature plan: Essentials (required for Pre Token Generation V2 access-token claim customization).
- OAuth flow: authorization code grant with PKCE; public SPA app client has no client secret.
- Managed login / authorization server: enabled.
- Resource server binding: the SPA authorization request sends `resource=https://api.tinlyt.tinlance.com`. The access token `aud` must equal this exact resource identifier.
- App client: allow only the production and explicitly approved preview client IDs. Do not accept arbitrary app clients.
- Token revocation: enabled (new app clients default to enabled); access tokens include `jti` and `origin_jti` for server-side revocation records.
- Access-token lifetime: configure to the shortest operationally acceptable value. The current browser client keeps the access token in memory and discards the refresh token returned by Cognito; users reauthenticate through managed login when the access token expires. Do not add browser refresh-token persistence. If persistent sessions are later required, implement a backend-for-frontend with server-side refresh-token storage and rotation.
- Signing: RS256; JWKS retrieved only from the exact user-pool issuer URL.

## Trusted claims

The verifier requires:

| Claim | Required value / source |
| --- | --- |
| `iss` | Exact Cognito user-pool issuer |
| `aud` | Exact HTTPS Tinlyt API resource identifier |
| `token_use` | `access` |
| `client_id` | Member of the configured app-client allowlist |
| `sub` | Cognito immutable user subject |
| `jti` | Token identifier, with revocation enabled |
| `tenant_id` | Added by the Pre Token Generation V2 trigger from an admin-controlled tenant assignment |
| `principal_type` | Constant `user`, set by the trigger |
| `cognito:groups` | Admin-managed group membership; maps to Platform roles |
| `scope` | OAuth scopes granted to the app client and user |

Never derive `tenant_id`, roles, or Platform scopes from browser request fields, client metadata, or user-editable profile attributes. For a single-tenant-per-user MVP, an admin-managed Cognito custom attribute can be the source only if end-user write permission is disabled and a trusted provisioning workflow assigns it. For multi-tenant users, use an authoritative membership store and resolve the active tenant server-side.

## Pre Token Generation V2 contract

The V2 trigger must add `tenant_id` and `principal_type=user` to the **access token**. It may add approved roles/scopes only from trusted server-side membership and entitlement data. The SPA intentionally ignores and does not persist the refresh token in Cognito's authorization-code response; the Platform stores its own access-token revocation records. The trigger must fail closed when tenant membership is missing, ambiguous, disabled, or unavailable. Do not trust client metadata or accept a tenant ID supplied by the SPA.

## Runtime composition

```python
verifier = create_cognito_access_token_verifier(
    region="eu-west-1",
    user_pool_id="<region>_<pool-id>",
    audience="https://api.tinlyt.tinlance.com",
    client_ids=("<public-spa-app-client-id>",),
)
resolver = JWKSPrincipalResolver(
    verifier=verifier,
    revocation_checker=production_revocation_checker,
)
server = serve(
    application.api,
    resolver,
    host="0.0.0.0",
    port=8080,
    jwks_provider=application.jwks_provider,
)
```

The reverse proxy/load balancer must enforce HTTPS, request-size limits, strict host/origin policy, and trusted forwarding headers. Do not expose the reference HTTP server directly to the internet.

## Not provisioned by this change

This code profile does not create a Cognito pool, app client, resource server, Lambda trigger, tenant store, KMS key, IAM role, API DNS record, or production service. Provision only after confirming current AWS credits, creating a least-privilege deployment role, and approving any cost outside credits. Do not reuse the separate ThreatFade Keycloak realm.
