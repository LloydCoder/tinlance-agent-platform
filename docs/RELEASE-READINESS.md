# Release Readiness

The platform milestone sequence is complete only when the repository's CI is green, the package coverage gate passes, boundary threat models have executable coverage, and no open pull requests/issues remain. Tagged release artifacts are built and Sigstore-signed by the release workflow. Production adoption additionally requires a real durable repository, secret manager, transactional outbox publisher, approved model/tool providers, isolated execution runtime, telemetry backend, backup/restore procedure and incident response controls.

The platform deliberately keeps those infrastructure adapters behind contracts so provider choices do not become authority logic.


## Agent certification gate

Before an agent is admitted to consequential execution, the independent **R10 Certification** workflow must pass. The certification suite is the executable boundary contract for tenant isolation, capability/version binding, approvals, idempotency, budgets, timeout/ambiguous outcomes, recovery, secret handling, hostile integrations, and evidence/audit causality. See [R10 Agent Certification](R10-CERTIFICATION.md).
