# Release Readiness

The canonical M0-M14 platform roadmap and post-M14 enterprise phases are complete only when the repository's CI and security gates are green. The repository enforces package quality, PostgreSQL migration/RLS/integrity tests, R10 certification, Reference Agents certification, CodeQL and secret scanning. Tagged release artifacts are built and Sigstore-signed by the release workflow.

M19 added evidence-backed production acceptance. M20 added provider-neutral risk, runtime-control, registry, attestation, cryptographic metadata and compliance-traceability contracts. M21 added an explicit readiness contract for external production dependencies. M22 added token, key lifecycle and attestation revocation controls. M23 added registry lifecycle, compatibility and provenance controls. M24 adds executable adversarial security regression gates.

## M24 gate

Every security regression case must declare an expected blocking outcome and evidence. A failed blocking case prevents release; adversarial evaluation never grants authority.

Production adoption additionally requires real durable infrastructure, secret management, isolated execution, telemetry, backup/restore, incident response, key management and operational ownership. Repository CI does not prove those external systems have been deployed.
