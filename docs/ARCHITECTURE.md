# Architecture

## System boundary

Tinlance Agent Platform is the governed execution and authority substrate beneath Tinlance Agentic OS.

It is domain-neutral and must not import or become dependent on FAS, FAS-Bench, FDSE, TADS, ReconOS, ThreatFade, Hezqara or FusionOps.

The platform establishes authority outside model reasoning and re-checks authorization at the final consequential side-effect boundary.

## Planes

### Authority plane
Identity, tenancy, authorization, policy, risk classification, approvals, budgets and governance.

### Execution plane
Agents, runtime, model gateway, tool/MCP gateway, sandbox, secrets, orchestration and multi-agent mediation.

### Control plane
Runtime control hooks, governed resource registry, attestation metadata, API and SDK surfaces.

### Evidence plane
Events, evidence, trajectory, observability, evaluation and compliance traceability.

### Operations plane
Durability, production readiness, SRE/error budgets, release assurance and independent certification evidence. Cryptographic metadata is provider-neutral; private key material remains external.

## Authority chain

principal -> tenant -> capability -> policy -> risk -> approval -> execution boundary -> evidence

Risk classification and control hooks can constrain an action but can never grant authority. Registry state, model output, tool output, attestation claims, external content and peer-agent messages are untrusted inputs until verified by the authoritative execution boundary.

## Dependency direction

contracts -> kernel -> services -> adapters -> apps

Contracts and kernel remain provider/framework neutral. Provider-specific adapters sit at the edge. Domain consumers use public contracts/SDK surfaces.

## Canonical milestones

M0-M14 are the canonical platform milestones. M15-M29 are the completed post-M14 enterprise-assurance sequence. The current definitions live in [docs/ROADMAP.md](ROADMAP.md).

## Platform vs Agentic OS

**Agent Platform owns:** identity, tenancy, authorization, policy, risk, approval authority, budgets, governed execution, sandbox/security boundaries, evidence and security events.

**Agentic OS owns:** users, sessions, tasks, workflows, agent applications, presentation, system integration and higher-level lifecycle.

The OS composes intent and lifecycle. The Platform establishes authority and executes consequential work.

## Production boundary

The repository provides contracts and reference implementations. A production deployment additionally requires durable PostgreSQL repositories, external secret management, approved model/tool providers, isolated execution infrastructure, telemetry collection, backup/restore, incident response, key management and operational controls.

Those deployment responsibilities must not be mistaken for authority logic embedded in the platform.

## Security invariants

1. Tenant identifiers are immutable across a governed request.
2. Capability possession cannot bypass policy.
3. Risk never grants authority.
4. Control hooks cannot bypass the authoritative execution boundary.
5. Registry state cannot authorize a resource.
6. Attestation is time-bounded and revocable.
7. Prohibited and secret-data actions cannot be approved into execution.
8. Every consequential tool call is re-authorized immediately before execution.
9. Approval binds tenant, run, action and resource and expires.
10. Child agents cannot widen parent authority or change tenant.
11. Untrusted content is not silently promoted to trusted context.
12. Secrets are execution-only handles.
13. Evidence is attributable and integrity-protected.
14. Evaluation and adversarial results never grant authority.
15. Recovery, capacity, release and assurance evidence gates can block release but cannot grant execution authority.
16. Security telemetry does not require sensitive payload capture.

## Design references

The architecture is consistent with current external guidance on agent identity/authorization, least privilege, high-impact approvals, isolation, adversarial evaluation, token protection, software supply-chain provenance and observability. External guidance informs the design; repository tests and contracts remain the implementation authority.

## Agent OS integration boundary

Agent OS is the higher-level lifecycle and experience layer. It sends intent to Platform through the versioned API contract and receives authoritative run, approval-reference, event and evidence-reference results.

The reference HTTP server is for contract/integration testing. Production deployments must place a hardened TLS/reverse-proxy boundary in front of it and inject a standards-based token verifier with issuer, audience, signature, expiry and lifecycle controls.

## Integration verification

The Agent OS boundary is covered by the API gateway and identity-binding tests. Authentication and tenant context are resolved server-side; request-body identity is never treated as authority.
