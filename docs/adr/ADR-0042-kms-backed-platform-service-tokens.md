# ADR-0042: KMS-backed Platform service tokens

- Status: Proposed
- Date: 2026-11-03
- Decision owners: Tinlance Agent Platform

## Context

TWI and World Intelligence transports require the Platform to mint short-lived, audience-bound
downstream access tokens. Provider-neutral issuer protocols existed, but no concrete production
signer was available. A service token must be accepted by the existing strict
`JWKSIdentityVerifier`, which requires `typ=at+jwt`, issuer, audience, subject, tenant,
principal type, client ID, token ID, issued-at, expiry and scope claims.

## Decision

Use asymmetric RSA signing through AWS KMS. The private key remains non-exportable. Publish the
matching public key as JWKS, use exact resource-server audiences, and limit token lifetime to
five minutes or less. Support verification-key overlap during rotation.

## Security properties

- Only RSA KMS keys with `SIGN_VERIFY` and RSASSA-PKCS1-v1_5 SHA-256 are accepted.
- The runtime requires `kms:GetPublicKey` and `kms:Sign` on the selected key only.
- JWKS responses expose only RSA public parameters and are size/key-count bounded.
- Token audience must be in an explicit allowlist.
- Tenant, subject and scopes must be supplied from a verified principal and Platform authorization decision.
- The signer does not authenticate users, resolve tenant membership, or grant permissions.
- Downstream tokens are short-lived and carry a unique `jti`.

## Consequences

The Platform must deploy the JWKS endpoint over HTTPS and configure each resource server with
the exact issuer, audience, algorithm, key ID and revocation strategy. Key rotation must publish
both old and new public keys for an overlap period that exceeds the maximum token lifetime and
JWKS cache TTL. Production composition and infrastructure provisioning remain separate release
gates; this ADR and its code do not imply that a production identity service is deployed.
