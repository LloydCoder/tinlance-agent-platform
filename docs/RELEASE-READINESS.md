# Release Readiness

The canonical M0-M14 platform roadmap and post-M14 enterprise phases are complete only when the repository's CI and security gates are green. The repository enforces package quality, PostgreSQL migration/RLS/integrity tests, R10 certification, Reference Agents certification, CodeQL and secret scanning. Tagged release artifacts are built and Sigstore-signed by the release workflow.

M19-M26 established production acceptance, control expansion, identity/trust, registry governance, adversarial security, recovery and capacity gates. M27 adds error budgets, alert thresholds and incident evidence.

## M27 gate

SRE acceptance requires explicit error-budget measurements, threshold rules and evidence-backed incident records. These contracts do not replace external telemetry, paging or compliance-audit infrastructure.

Production adoption still requires real durable infrastructure, telemetry, incident response, backup/restore, key management and operational ownership.
