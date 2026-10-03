# Release Readiness

The canonical M0-M14 platform roadmap and post-M14 enterprise phases are complete only when the repository's CI and security gates are green. The repository enforces package quality, PostgreSQL migration/RLS/integrity tests, R10 certification, Reference Agents certification, CodeQL and secret scanning. Tagged release artifacts are built and Sigstore-signed by the release workflow.

M19-M25 established production acceptance, control expansion, identity/trust, registry governance, adversarial security and recovery gates. M26 adds measurable capacity envelopes and tenant economic quotas.

## M26 gate

Capacity acceptance requires evidence-backed throughput, p95/p99 latency and concurrency measurements against an explicit envelope. Tenant quotas constrain admission across concurrency, tool calls, token units and cost units.

Production performance remains infrastructure- and provider-dependent; repository CI does not claim a fixed production capacity.
