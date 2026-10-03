# M22 — Identity, Cryptography & Attestation

M22 hardens provider-neutral token validation, sender-constraint metadata, key lifecycle and attestation revocation contracts.

Controls include exact issuer/audience validation, validity windows, nonce binding, sender-key metadata, explicit active/retired/revoked key states, one-active-key lifecycle validation, and attestation expiry/revocation.

Private keys, bearer tokens and provider credentials remain outside the Platform contract layer. Provider adapters remain responsible for cryptographic verification and KMS/HSM operations.

The design follows current NIST token/assertion protection guidance, OAuth sender-constrained token practices and OpenID Connect issuer/audience/nonce validation requirements.

M22 is complete only when exports, tests, documentation and every CI/security workflow are green.
