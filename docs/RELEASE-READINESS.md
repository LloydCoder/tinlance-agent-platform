# Release Readiness

The canonical M0-M14 platform roadmap and post-M14 enterprise phases are complete only when the repository's CI and security gates are green. The repository enforces package quality, PostgreSQL migration/RLS/integrity tests, R10 certification, Reference Agents certification, CodeQL and secret scanning. Tagged release artifacts are built and Sigstore-signed by the release workflow.

M19 added evidence-backed production acceptance. M20 added provider-neutral risk, runtime-control, registry, attestation, cryptographic metadata and compliance-traceability contracts. M21 adds an explicit readiness contract for external production dependencies.

Production adoption additionally requires a real durable repository, secret manager, transactional outbox publisher, approved model/tool providers, isolated execution runtime, telemetry backend, backup/restore procedure, incident-response controls, key management and operational ownership. Repository CI proves repository behavior; it does not prove those external controls have been deployed.

## Agent certification gate

Before an agent is admitted to consequential execution, the independent **R10 Certification** workflow must pass. The certification suite is the executable boundary contract for tenant isolation, capability/version binding, approvals, idempotency, budgets, timeout/ambiguous outcomes, recovery, secret handling, hostile integrations, and evidence/audit causality. See [R10 Agent Certification](R10-CERTIFICATION.md).

## M20 gate

M20 requires all new package contracts to be exported, installed by the wheel build, covered by tests and kept outside the authoritative execution path.

## M21 gate

M21 requires explicit readiness evidence for database, outbox, secret manager, sandbox, telemetry, backup, incident response and ownership. The contract certifies evidence presence; it does not claim those systems are deployed by CI.
