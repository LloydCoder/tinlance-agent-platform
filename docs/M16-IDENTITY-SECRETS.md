# M16 — Enterprise Identity, Secrets & Trust

## Scope

M16 hardens the Platform's identity and secret boundaries for production adapters. The repository remains provider-neutral: cryptographic token verification and secret storage are external responsibilities, while the Platform validates the claims and execution scope it consumes.

## Controls

- exact issuer and audience validation;
- assertion validity-window validation;
- normalized subject, tenant and token identity;
- versioned execution-scoped secret handles;
- immutable tenant/principal/agent/execution/capability binding;
- explicit provider adapter protocols;
- no secret authority from model/tool/client assertions;
- tests for issuer/audience confusion, expiry and cross-tenant secret use.

## External alignment

NIST's September 2026 IR 8587 emphasizes token/assertion protection, key management, token verification, lifecycle controls and continuous monitoring. NIST's current agent identity project likewise focuses on identification, authentication, authorization, auditing and non-repudiation for software agents. OAuth 2.0 Security BCP (RFC 9700) recommends least privilege, audience restriction and sender-constrained access tokens where applicable.

These references inform the adapter boundary; they do not make provider-specific cryptographic verification part of the Platform kernel.
