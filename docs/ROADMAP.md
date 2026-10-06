# Canonical Agent Platform Roadmap

This is the **authoritative milestone sequence** for Tinlance Agent Platform. It supersedes historical implementation-order labels retained in status documents and commit history.

**Canonical sequence**

M0 Foundation → M1 Identity → M2 Authorization → M3 Approval → M4 Runtime → M5 Model Gateway → M6 Tool/MCP Gateway → M7 Sandbox → M8 Orchestration → M9 Memory → M10 Evidence/Event → M11 Observability → M12 Evaluation → M13 Domain SDK → M14 Enterprise

## Milestone contracts

| Milestone | Required capability | Completion evidence |
|---|---|---|
| M0 | Contracts, kernel, package boundaries, PostgreSQL RLS, threat model | Architecture, SQL and boundary tests |
| M1 | Normalized principals, agent identity/versioning, tenant binding | Identity contracts and conformance tests |
| M2 | Explicit capabilities, deny-by-default authorization, complete mediation | Positive/negative authorization tests |
| M3 | Resumable human review, exact action binding, expiry | Approval lifecycle and replay/scope tests |
| M4 | Fail-closed runtime lifecycle, hard budgets, terminal-state integrity | Runtime invariants and failure-path tests |
| M5 | Provider-neutral model port and usage validation | Model gateway contracts and usage tests |
| M6 | Scoped tool/MCP registration, resource binding, transport isolation | Tool/MCP conformance and tenancy tests |
| M7 | Isolated workspace plus command/path/network policy | Sandbox isolation and fail-closed tests |
| M8 | Agent runner, handoff/delegation and resumable execution | Orchestration and authority-propagation tests |
| M9 | Tenant-scoped memory/context, trust labels, classification and redaction | Memory isolation and secret-redaction tests |
| M10 | Append-oriented events/evidence, audit records and trajectory integrity | Evidence/event and integrity tests |
| M11 | Correlated traces, metrics and security events | Observability correlation and redaction tests |
| M12 | Deterministic safety/regression evaluation | Evaluation corpus and release-gate tests |
| M13 | Stable public consumer surface and declarative domain registration | SDK compatibility/conformance tests |
| M14 | Enterprise integrity, production configuration, recovery, supply chain and release gates | RLS/integrity, supply-chain, release and operational contracts |

## Completion definition

A milestone is considered implemented only when its capability exists in the repository **and** its security invariants, executable tests, documentation and boundary contracts are reconciled.

A passing CI run is evidence for the repository gates; it is not evidence that external production infrastructure has been deployed.

## Architectural boundary

The platform is the governed execution substrate beneath Tinlance Agentic OS. It must remain independent from:

- FAS / FAS-Bench
- FDSE
- TADS / ReconOS
- ThreatFade
- Hezqara
- FusionOps
- Tinlance Agentic OS

These systems consume platform contracts/SDK surfaces; they do not become platform dependencies.

## Production boundary

Reference implementations intentionally remain provider-neutral. Production deployments must supply durable persistence, secret management, isolated compute, telemetry infrastructure, backup/restore, incident response, provider-specific controls and operational ownership.

The production acceptance criteria are maintained in [ENTERPRISE-BASELINE.md](ENTERPRISE-BASELINE.md).

## Security invariants carried through every milestone

1. Tenant scope is immutable.
2. Capability possession does not bypass policy.
3. Prohibited and secret-data actions cannot be approved.
4. Consequential actions are re-authorized immediately before execution.
5. Approval is tenant/run/action/resource bound and expires.
6. Child agents cannot widen authority or change tenant.
7. Untrusted content cannot silently become trusted instructions.
8. Secrets remain execution-only handles.
9. Evidence remains attributable and integrity-protected.
10. Evaluation never grants authority.

## Documentation authority

When documentation conflicts:

1. **Current implementation and executable tests** define what is actually implemented.
2. This roadmap defines the canonical product milestone vocabulary.
3. [ARCHITECTURE.md](../ARCHITECTURE.md) defines the stable system boundary and invariants.
4. [ENTERPRISE-BASELINE.md](ENTERPRISE-BASELINE.md) defines deployment/enterprise acceptance.
5. Historical status documents and ADRs provide traceability and rationale; they do not override the canonical definitions.

Any change to milestone meaning requires updating the roadmap, affected architecture/security documentation, tests and README in the same change.

## Non-goals

The platform does not become an application or domain product. It does not grant authority from model confidence, prompt content, retrieved intelligence, tool registration, evaluation output or external data alone.

# Post-M14 Enterprise Evolution

M14 closes the canonical Agent Platform roadmap. The following phases are the **post-M14 production-maturity sequence** and must not be confused with missing canonical M0–M14 milestones.

## M15 — Production Infrastructure & Recovery

**Objective:** convert reference durability/execution boundaries into production-ready contracts for durable state, recovery and high availability.

Required outcomes:
- transactional outbox and durable publication contract;
- durable run/execution state with crash recovery;
- durable approval and idempotency adapters;
- lease/ownership semantics for distributed workers;
- cancellation and retry semantics that preserve execution identity;
- PostgreSQL production adapter contracts with tenant-safe transactions;
- backup/restore and disaster-recovery acceptance tests;
- readiness checks that distinguish dependency health from application liveness.

## M16 — Enterprise Identity, Secrets & Trust

**Objective:** integrate production identity and secret infrastructure without moving authority into providers.

Required outcomes:
- OIDC/OAuth/workload-identity adapters;
- agent/service identity lifecycle and revocation;
- key/token rotation contracts;
- external secret-manager adapter contracts;
- KMS/HSM integration boundaries where required;
- sender-constrained credential support where applicable;
- authorization and identity conformance tests against provider adapters.

## M17 — Agent Interoperability

**Objective:** make remote-agent and protocol interoperability safe without allowing interoperability to grant authority.

Required outcomes:
- MCP production conformance;
- A2A/remote-agent integration boundary;
- agent discovery and capability advertisement;
- authenticated delegation and authority attenuation;
- protocol/version negotiation;
- cross-agent provenance and audit causality;
- hostile-peer and confused-deputy tests.

## M18 — Reliability, Observability & Continuous Evaluation

**Objective:** make production behavior measurable, testable and continuously defensible.

Required outcomes:
- OpenTelemetry-native traces/metrics/log correlation;
- security-event and consequential-action correlation;
- SLOs, error budgets and capacity measurements;
- load, stress, chaos and failover tests;
- continuous adversarial evaluation;
- cost/latency/tool-call budgets as operational signals;
- production diagnostic and incident-evidence workflows.

## M19 — Enterprise Certification & Production GA

**Objective:** establish the final release gate for production operation.

Required outcomes:
- full conformance and compatibility matrix;
- tenant-isolation certification;
- authorization/approval/sandbox certification;
- supply-chain provenance and signed release verification;
- disaster-recovery and rollback certification;
- penetration/red-team validation;
- upgrade compatibility and migration certification;
- incident-response exercises;
- documented production acceptance and operational ownership.

### Serial completion rule

M15 through M19 are strictly serial. A phase is complete only when its implementation, tests, security invariants, documentation and CI/release gates are green. The next phase must not begin while the preceding phase has a failing gate or unresolved blocker.


## M20–M29 Final Enterprise Assurance Track

The following sequence is the final finite enterprise-assurance program. It extends the M15–M19 production-maturity work without reopening completed canonical milestones.

### M20 — Enterprise Control Expansion
Add provider-neutral risk classification, runtime control hooks, governed resource registry, agent/workload/artifact/runtime attestation, cryptographic metadata and control-to-evidence compliance mappings.

### M21 — Production Infrastructure
Exercise the platform against durable PostgreSQL, outbox/queue infrastructure, external secret management, isolated runtime/sandbox supervision, telemetry backends, health/readiness and deployment boundaries.

### M22 — Identity, Cryptography & Attestation
Harden OIDC/OAuth/workload identity, credential/key rotation, token protection, sender-constrained credentials where applicable, runtime/artifact attestation and revocation.

### M23 — Registry & Ecosystem Governance
Establish lifecycle, compatibility, provenance, versioning and revocation controls for agents, tools, MCP servers, models, policies, runtimes and remote agents.

### M24 — Adversarial Agent Security
Continuously test prompt/goal hijacking, tool misuse, privilege abuse, memory/context poisoning, malicious MCP/remote agents, confused-deputy behavior, data exfiltration, sandbox escape and cascading failures against the governed boundary.

### M25 — Distributed Reliability & Disaster Recovery
Validate worker crash recovery, database/queue failure, partitions, retries, duplicate delivery, failover, backup/restore, RTO/RPO and chaos scenarios.

### M26 — Performance & Economic Governance
Measure throughput, concurrency, p95/p99 latency, queue/database saturation, admission control, quotas, backpressure, token/tool/cost budgets and noisy-neighbor isolation.

### M27 — Enterprise SRE & Compliance
Operationalize OpenTelemetry, SLOs, error budgets, alerts, incident evidence, ownership, control mappings and enterprise evidence packages.

### M28 — Supply Chain & Release Assurance
Harden SBOM, provenance, signatures, dependency security, compatibility, migrations, rollback, upgrade safety and release attestations.

### M29 — Independent Enterprise Assurance
Run independent penetration/red-team testing, destructive recovery exercises, production acceptance, evidence review and final enterprise certification.

### Finalization rule

M20–M29 are strictly serial. A phase is complete only when implementation, security invariants, executable tests, documentation and every applicable CI/workflow gate are green. After M29, the finite roadmap ends and the Platform enters continuous enterprise assurance.


## Final M15-M29 status

All post-M14 enterprise phases M15-M29 have completed their repository implementation, tests, documentation and applicable CI/security gates.

| Phase | Repository state |
|---|---|
| M15-M19 | Complete |
| M20 | Complete |
| M21 | Complete |
| M22 | Complete |
| M23 | Complete |
| M24 | Complete |
| M25 | Complete |
| M26 | Complete |
| M27 | Complete |
| M28 | Complete |
| M29 | Complete |

This status is a repository-level statement. External production infrastructure, independent penetration testing, disaster-recovery exercises and customer compliance evidence remain deployment/assurance activities and are not implied by repository CI.

## Supplemental production-runtime hardening

The following labels are implementation traceability only and do not redefine the canonical M0-M14 vocabulary or reopen the completed M15-M29 enterprise track.

### M13.4 — Budget and Resource Governance

The consequential execution boundary now requires exact tenant/agent/run/action/resource budget scope, idempotent reservation identity, atomic tenant quota admission, and fail-closed settlement/release semantics. This hardens the M4 hard-budget invariant and M26 economic-governance contracts.

Acceptance requires adversarial coverage for cross-tenant scope, reservation replay, parallel quota admission, exhaustion, settlement and release. See [M13-4-BUDGET-RESOURCE-GOVERNANCE.md](production-runtime/M13-4-BUDGET-RESOURCE-GOVERNANCE.md).
