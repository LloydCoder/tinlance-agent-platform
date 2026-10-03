# Enterprise Conformance

The platform's enterprise claim is based on executable controls rather than milestone labels alone.

## Canonical sequence

M0 -> M1 -> M2 -> M3 -> M4 -> M5 -> M6 -> M7 -> M8 -> M9 -> M10 -> M11 -> M12 -> M13 -> M14

M14 closes the canonical roadmap. M15-M19 complete the first post-M14 production-maturity sequence. M20 begins the final enterprise-control expansion track.

## Post-M14 conformance

- **M15:** durable outbox/recovery contracts and worker ownership leases.
- **M16:** verified federated identity claims and execution-scoped secret handles.
- **M17:** secure remote-agent discovery metadata and authority-attenuating delegation.
- **M18:** tenant/run/execution/trace correlation, SLO measurement and safety-aware evaluation gates.
- **M19:** evidence-backed production acceptance and GA certification contract.
- **M20:** risk classification, runtime control hooks, tenant-bound resource registry, attestation claims, cryptographic metadata and compliance traceability.

## Invariants

- Tenant identity is bound at request, task, run, model and tool boundaries.
- Authorization is evaluated outside model reasoning.
- Risk can constrain but never grant authority.
- Runtime control hooks can deny or require review but cannot bypass the authoritative execution boundary.
- Registry records describe lifecycle state and provenance; registration does not authorize use.
- Attestation is time-bounded and cannot widen authority.
- High-risk or irreversible actions remain approval-gated.
- Tool and MCP calls are completely mediated against capability, action and resource.
- Model providers can be tenant/agent allowlisted and cannot exceed requested output budgets.
- Context excludes untrusted content by default and redacts secret-like material.
- Evidence is bounded, tenant-scoped and independently hash-verifiable.
- Trajectory is append-only in the reference store and hash-chain verifiable.
- Events are immutable, tenant-scoped and reject sensitive fields.
- Runtime state transitions and turn/tool budgets are enforced before consequential side effects.
- Remote interoperability cannot grant authority; consequential work re-enters the governed execution boundary.
- Evaluation does not grant authority.
- Domain SDKs remain consumers; domain products do not become platform dependencies.

## Production boundary

The repository provides a governed, provider-neutral core and reference adapters. Customer production deployment still requires real durable stores, secret management, approved model/tool providers, isolated execution infrastructure, telemetry backends, backup/restore, incident response, key management and operational SLOs.

M19 and M20 make the evidence and control requirements explicit; they do not substitute test doubles for deployed infrastructure.

Conformance is enforced by CI on every pull request.
