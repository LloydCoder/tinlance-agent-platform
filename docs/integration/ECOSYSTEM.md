# Tinlance Agent Ecosystem Integration

Tinlance Agent Platform is the authoritative execution/authority plane beneath the other three repositories.

```mermaid
flowchart LR
    D[Tinlance Agent Developer] --> O[Tinlance Agent OS]
    O --> S[Tinlance Agent Platform SDK]
    S --> P[Tinlance Agent Platform]
    P --> A[Identity / tenancy / policy / approvals]
    P --> X[Governed execution / sandbox / tools]
    P --> V[Authoritative evidence / audit]
    C[Ecosystem Conformance] -. gates .-> D
    C -. gates .-> O
    C -. gates .-> S
    C -. gates .-> P
```

The Platform does not depend on TADL, Agent OS, or the SDK for authority. They are consumers of the Platform's versioned contracts. The Platform SDK is a developer transport surface; Agent OS is a higher-level lifecycle/control plane; TADL is a developer artifact plane.

**Canonical wire contract:** API version 1.1, `POST /v1/agent-platform`, with `governed-execution.v1` for consequential tool mediation.

The integration boundary binds tenant and subject to the authenticated principal, re-checks authorization at the consequential side-effect boundary, enforces idempotency for guarded operations, and emits authoritative evidence/events. Untrusted model/tool/external content never becomes authority merely by crossing an upstream layer.

The repository's HTTP server is a reference contract boundary. Production deployments must add the hardened TLS, token verification, durable persistence, secrets, isolated runtime, telemetry, and operational controls described by the production documentation.

The four-repository integration gate is maintained from the TADL repository and uses pinned commit SHAs so compatibility is reproducible rather than dependent on moving branches.

## Conformance

The TADL-hosted conformance suite is the executable compatibility gate for the four repositories. It validates API 1.1 interoperability, authenticated principal binding, idempotency, trace propagation, transport security, and authority dependency direction against pinned revisions. Production infrastructure certification remains separate.

## Production identity

The Platform now includes a JWKS-backed JWT verification adapter for production identity boundaries. Verified issuer, audience, subject, tenant and validity claims feed the Platform authorization boundary; identity verification never grants execution authority. See `docs/production-runtime/M13-2-REAL-IDENTITY.md`.
