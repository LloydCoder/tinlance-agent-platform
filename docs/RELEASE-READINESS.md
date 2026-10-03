# Release Readiness

The canonical M0-M14 platform roadmap and post-M14 enterprise phases are complete only when the repository's CI and security gates are green. The repository enforces package quality, PostgreSQL migration/RLS/integrity tests, R10 certification, Reference Agents certification, CodeQL and secret scanning. Tagged release artifacts are built and Sigstore-signed by the release workflow.

M19-M27 established production acceptance, control expansion, identity/trust, registry governance, adversarial security, recovery, capacity and SRE gates. M28 adds explicit release provenance and rollback evidence contracts.

## M28 gate

A release must carry source revision, algorithm-qualified artifact digest, SBOM, provenance and signature evidence. Upgrade plans must identify a migration and rollback reference. The tagged release workflow is responsible for building/signing artifacts; the Platform contract only models the evidence boundary.

Production release still requires deployment-specific change management, rollback execution and operational ownership.
