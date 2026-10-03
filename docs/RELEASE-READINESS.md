# Release Readiness

The canonical M0-M14 platform roadmap and post-M14 enterprise phases are complete only when the repository's CI and security gates are green. The repository enforces package quality, PostgreSQL migration/RLS/integrity tests, R10 certification, Reference Agents certification, CodeQL and secret scanning. Tagged release artifacts are built and Sigstore-signed by the release workflow.

M19 added evidence-backed production acceptance. M20 added provider-neutral risk, runtime-control, registry, attestation, cryptographic metadata and compliance-traceability contracts. M21 added an explicit readiness contract for external production dependencies. M22 added token, key lifecycle and attestation revocation controls. M23 adds registry lifecycle, compatibility and provenance controls.

Production adoption additionally requires a real durable repository, secret manager, transactional outbox publisher, approved model/tool providers, isolated execution runtime, telemetry backend, backup/restore procedure, incident-response controls, key management and operational ownership. Repository CI proves repository behavior; it does not prove those external controls have been deployed.

## M23 gate

M23 requires registry resources to carry provenance and algorithm-qualified digests, and requires compatibility checks to fail closed. Registry state remains descriptive and cannot grant authorization.
