# M28 — Supply Chain & Release Assurance

M28 adds release provenance, artifact digest, SBOM, signature and rollback contracts.

A release manifest requires a source revision, algorithm-qualified artifact digest, SBOM reference, provenance reference and signature reference. Upgrade plans require migration and rollback evidence.

The repository release workflow already builds distributions, generates an SBOM and signs release artifacts. M28 makes the evidence model explicit in the Platform's operations contracts.

M28 is complete only when release contracts, tests, documentation and every CI/security workflow are green.
