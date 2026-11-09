# M22 — Identity, Cryptography & Attestation

## Objective

M22 makes identity-token context, sender binding, cryptographic key lifecycle and attestation trust transitions explicit, deterministic and fail-closed. These are provider-neutral contract checks. They do not replace the Platform's authoritative identity verifier, policy engine, credential store or cryptographic provider.

## Token security context

`TokenSecurityContext` validates the claims needed by a caller after the token's cryptographic signature and trust chain have been verified by the configured identity adapter.

- Issuer comparison is exact; issuer, subject and token identifier are mandatory.
- Audience must contain at least one non-empty, unique value. The caller must supply the exact resource audience it expects.
- `issued_at`, `expires_at` and optional `not_before` must be timezone-aware. The expiry must be after issuance; optional not-before must lie within the token validity window.
- A token is rejected before issuance, before not-before, and at or after expiry. There is no implicit clock-skew allowance in this contract; deployments that need bounded skew must apply a documented policy at the verified-token adapter boundary.
- When a request expects a nonce, the claim must be present and match using constant-time comparison.
- A sender-bound token must be checked against the request's independently verified sender-key thumbprint. A token carrying sender-binding metadata is rejected when the caller omits that request binding.
- The thumbprint format is the unpadded base64url encoding of a 32-byte SHA-256 value (43 canonical characters).

The context object is not a JWT parser or signature verifier. It does not validate JOSE headers, signing algorithms, key identifiers, issuer metadata discovery, JWKS rotation, certificate chains, DPoP proof signatures, HTTP method/URI binding, DPoP `ath`, proof freshness or replay caches. A raw thumbprint supplied by an untrusted request is not proof of possession. The caller must derive the expected thumbprint only after validating the applicable proof (for example, DPoP or mutual-TLS certificate binding).

## Cryptographic key lifecycle

`KeyVersion` supports explicit `active`, `retired` and `revoked` states.

- Every key version has a non-empty key identifier, version, algorithm label and timezone-aware activation time.
- Retired versions require a retirement timestamp; revoked versions require a revocation timestamp. Transition timestamps cannot precede activation, and revocation cannot precede retirement.
- Active versions cannot carry retirement or revocation timestamps.
- A `KeyLifecycle` contains versions for one key identifier, rejects duplicate versions and requires exactly one active version at selection time.
- A future-dated active version is not usable; overlapping active versions are rejected rather than silently choosing one.
- Private key bytes, symmetric secrets and provider credentials are never represented in these records. KMS/HSM adapters retain key material and enforce provider-side IAM, exportability, backup, rotation, destruction and audit controls.

The lifecycle record is metadata, not a key store or signing/decryption API. Algorithm labels are not an algorithm allowlist; deployments must apply current cryptographic policy and transition guidance before a provider key can be used.

## Attestation trust and revocation

- Revocation records require an attestation identifier, a non-empty reason and a timezone-aware revocation timestamp.
- Trust records require a non-empty attestation identifier and timezone-aware expiry; optional validity start must precede expiry.
- A revoked attestation requires an explicit revocation timestamp and is never usable.
- Trust is usable only inside its validity interval. Expired, not-yet-valid and revoked attestations fail closed.

This package does not fetch revocation feeds, verify attestation signatures or certificate chains, persist revocation state, or guarantee propagation latency. A production adapter must authenticate the evidence source, persist revocations durably, invalidate caches, define freshness/availability SLOs and fail closed when required revocation status cannot be established.

## Authority and deployment boundary

These contracts do not grant authority. Identity and cryptographic metadata cannot override tenant binding, capability checks, policy decisions, approval requirements, execution budgets or the Platform's authorization boundary.

The following remain deployment responsibilities and must be evidenced before production acceptance:

1. signature and issuer trust verification using a configured identity provider;
2. audience and nonce policy bound to the request transaction;
3. actual DPoP or mutual-TLS proof verification and replay protection where sender-constrained tokens are used;
4. KMS/HSM-backed private-key custody, access policy, rotation, backup and destruction;
5. durable revocation distribution, cache invalidation and emergency key-compromise procedures;
6. attestation-chain validation, freshness, verifier identity and revocation source integrity;
7. operational evidence for revocation propagation, key rotation and recovery.

M21's production-readiness evidence gate remains authoritative for external infrastructure. A green M22 contract suite is not evidence that a production identity provider, KMS/HSM, revocation service or attestation verifier has been deployed.

## Standards alignment

The contract is informed by:

- [RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700.html), including audience restriction and sender-constrained access-token guidance.
- [RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449.html). DPoP requires cryptographic proof-of-possession and replay controls beyond the metadata comparison implemented here.
- [OpenID Connect Core 1.0 — ID Token Validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation), including issuer, audience, time and nonce validation.
- [NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final), final key-management guidance covering key material protection, metadata and lifecycle management.
- [NIST SP 800-57 Rev. 6 project page](https://csrc.nist.gov/Projects/Key-Management/Key-Management-Guidelines), which listed Rev. 6 as an initial public draft on the date this phase was prepared. It is not treated as a final standard here.

## Completion criteria

M22 is complete only when the package exports, adversarial unit tests, type/lint/coverage gates, documentation and all required CI/security workflows pass on the exact PR head, the PR is merged, and post-merge workflows pass. Completion certifies repository contracts only; external production evidence remains separate.
