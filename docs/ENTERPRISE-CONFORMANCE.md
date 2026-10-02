# Enterprise Conformance

The platform's enterprise claim is based on executable controls rather than milestone labels alone.

## Canonical sequence

M0 -> M1 -> M2 -> M3 -> M4 -> M5 -> M6 -> M7 -> M8 -> M9 -> M10 -> M11 -> M12 -> M13 -> M14

M14 closes the canonical roadmap. M15-M19 are the completed post-M14 production-maturity sequence.

## Post-M14 conformance

- **M15:** durable outbox/recovery contracts and worker ownership leases.
- **M16:** verified federated identity claims and execution-scoped secret handles.
- **M17:** secure remote-agent discovery metadata and authority-attenuating delegation.
- **M18:** tenant/run/execution/trace correlation, SLO measurement and safety-aware evaluation gates.
- **M19:** evidence-backed production acceptance and GA certification contract.

## Invariants

- Tenant identity is bound at request, task, run, model and tool boundaries.
- Authorization is evaluated outside model reasoning.
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

M19 makes these requirements explicit through an evidence-backed acceptance contract; it does not substitute test doubles for deployed infrastructure.

Conformance is enforced by CI on every pull request.