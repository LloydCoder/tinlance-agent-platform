# Tinlance Agent Ecosystem Integration

Tinlance Agent Platform is the authoritative execution/authority plane beneath the other three repositories.

```mermaid
flowchart LR
    D[Tinlance Agent Developer / TADL] --> O[Tinlance Agent OS]
    O --> S[Tinlance Agent Platform SDK]
    S --> P[Tinlance Agent Platform]
    P --> A[Identity / tenancy]
    P --> Z[Authorization / policy / approvals]
    P --> X[Budgets / sandbox / tools / MCP]
    P --> V[Evidence / audit / observability]
    C[Ecosystem Conformance] -. gates .-> D
    C -. gates .-> O
    C -. gates .-> S
    C -. gates .-> P
```

The Platform does not depend on TADL, Agent OS, or the SDK for authority. They are consumers of the Platform's versioned contracts. The Platform SDK is a developer transport surface; Agent OS is a higher-level lifecycle/control plane; TADL is a developer artifact plane.

**Canonical wire contract:** API version 1.1, `POST /v1/agent-platform`, with `governed-execution.v1` for consequential tool mediation.

The integration boundary binds tenant and subject to the authenticated principal, re-checks authorization at the consequential side-effect boundary, enforces idempotency for guarded operations, and emits authoritative evidence/events. Untrusted model/tool/external content never becomes authority merely by crossing an upstream layer.

The repository's HTTP server is a reference contract boundary. Production deployments must add the hardened TLS, token verification, durable persistence, secrets, isolated runtime, telemetry, and operational controls described by the production documentation.

The four-repository integration gate is maintained from the Agent Developer repository and uses pinned commit SHAs so compatibility is reproducible rather than dependent on moving branches.

## Milestone vocabulary

M0–M14 remain the canonical Agent Platform roadmap. The supplemental M13.1–M13.3 production-runtime hardening labels are retained for implementation traceability and do **not** redefine the canonical M13 Domain SDK or M14 Enterprise milestones. Post-M14 production maturity is governed by M15–M29.

## Conformance

The TADL-hosted conformance suite is the executable compatibility gate for the four repositories. It validates API 1.1 interoperability, authenticated principal binding, idempotency, trace propagation, transport security, and authority dependency direction against pinned revisions. Production infrastructure certification remains separate.

## Production identity

The Platform now includes a JWKS-backed JWT verification adapter for production identity boundaries. Verified issuer, audience, subject, tenant and validity claims feed the Platform authorization boundary; identity verification never grants execution authority. See `docs/production-runtime/M13-2-REAL-IDENTITY.md`.

## Authorization enforcement

M13.3 makes the authorization boundary explicit: authenticated identity, registered capability, policy decision, required bound approval and runtime controls must all permit the operation before the side-effect boundary. Approval binding includes tenant, run, action, resource and intent fingerprint.
