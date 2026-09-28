# Repository Agent Instructions

This repository is the generic Tinlance Agent Platform substrate. Keep FDSE, TADS, ThreatFade, Hezqara and ReconOS outside the kernel.

Dependency direction: contracts -> kernel -> services -> adapters -> apps. Core packages must not import adapters, provider SDKs, web frameworks, databases, or domain repositories.

Security invariants:
- capability never implies authority
- model/external content never grants authority
- cross-tenant access fails closed
- every consequential side effect is attributable and policy-mediated
- prohibited actions cannot be approved
- secrets are never normal model-context or trajectory data

Make boundaries executable with tests. Add ADRs for architectural changes.
