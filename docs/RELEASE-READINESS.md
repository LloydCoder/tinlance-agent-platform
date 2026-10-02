# Release Readiness

The canonical M0-M14 platform roadmap and the post-M14 M15-M19 enterprise evolution sequence are complete only when the repository's CI and security gates are green. The current repository enforces package quality, PostgreSQL migration/RLS/integrity tests, R10 certification, Reference Agents certification, CodeQL and secret scanning. Tagged release artifacts are built and Sigstore-signed by the release workflow.

M19 adds an explicit production acceptance contract requiring evidence for identity, authorization, governed execution, durability/recovery, secrets, isolation, observability, evaluation, supply chain, interoperability and operational ownership.

Production adoption additionally requires a real durable repository, secret manager, transactional outbox publisher, approved model/tool providers, isolated execution runtime, telemetry backend, backup/restore procedure and incident-response controls. Repository CI proves repository behavior; it does not prove those external controls have been deployed.

## Agent certification gate

Before an agent is admitted to consequential execution, the independent **R10 Certification** workflow must pass. The certification suite is the executable boundary contract for tenant isolation, capability/version binding, approvals, idempotency, budgets, timeout/ambiguous outcomes, recovery, secret handling, hostile integrations, and evidence/audit causality. See [R10 Agent Certification](R10-CERTIFICATION.md).