# Enterprise Conformance

The platform's enterprise claim is based on executable controls rather than milestone labels alone.

## Canonical sequence

M0 -> M1 -> M2 -> M3 -> M4 -> M5 -> M6 -> M7 -> M8 -> M9 -> M10 -> M11 -> M12 -> M13 -> M14

M14 closes the canonical roadmap. M15-M25 are complete repository-level enterprise evolution phases. M26 is the active performance and economic-governance phase.

## Post-M14 conformance

- **M15:** durable outbox/recovery contracts and worker ownership leases.
- **M16:** verified federated identity claims and execution-scoped secret handles.
- **M17:** secure remote-agent discovery metadata and authority-attenuating delegation.
- **M18:** tenant/run/execution/trace correlation, SLO measurement and safety-aware evaluation gates.
- **M19:** evidence-backed production acceptance and GA certification contract.
- **M20:** risk classification, runtime control hooks, tenant-bound resource registry, attestation claims, cryptographic metadata and compliance traceability.
- **M21:** evidence-backed readiness contract for the external production dependency boundary.
- **M22:** token validation, sender-constraint metadata, key lifecycle and attestation revocation contracts.
- **M23:** registry lifecycle, compatibility, provenance, digest and revocation controls.
- **M24:** executable adversarial security regression corpus and fail-closed release gate.
- **M25:** recovery objectives, failure-mode drills and RTO/RPO release gate.
- **M26:** capacity envelopes and tenant economic quotas for admission governance.

## Invariants

- Tenant identity is bound at request, task, run, model and tool boundaries.
- Authorization is evaluated outside model reasoning.
- Risk can constrain but never grant authority.
- Runtime control hooks can deny or require review but cannot bypass the authoritative execution boundary.
- Registry records describe lifecycle, compatibility and provenance; registration does not authorize use.
- Revoked resources are not usable.
- Attestation is time-bounded, revocable and cannot widen authority.
- Token issuer and audience are explicitly validated; nonce binding is enforced when requested.
- Sender-constraint metadata does not replace authorization.
- Key lifecycle state is explicit and private key material remains external.
- Adversarial evaluation never grants authority and a failed blocking case prevents release.
- Recovery evidence measures resilience and cannot be replaced by a green unit test alone.
- Capacity and quota controls constrain admission but do not grant authority.
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

M19-M26 make the evidence, readiness, trust, ecosystem-governance, adversarial-security, recovery and capacity requirements explicit; they do not substitute test doubles for deployed infrastructure.

Conformance is enforced by CI on every pull request.
