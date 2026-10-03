# Release Readiness

The canonical M0-M14 platform roadmap and post-M14 enterprise phases are complete only when the repository's CI and security gates are green. The repository enforces package quality, PostgreSQL migration/RLS/integrity tests, R10 certification, Reference Agents certification, CodeQL and secret scanning. Tagged release artifacts are built and Sigstore-signed by the release workflow.

M19-M24 established production acceptance, control expansion, identity/trust, registry governance and adversarial security gates. M25 adds executable recovery objectives and RTO/RPO drill acceptance.

## M25 gate

Every recovery drill must declare RTO/RPO objectives and evidence. A drill that exceeds either objective prevents the recovery gate from passing. The contract measures recovery behavior; it does not claim that external backup, failover or regional infrastructure is deployed.

Production adoption still requires real durable infrastructure, backup/restore, failover, incident response, key management, telemetry and operational ownership.
