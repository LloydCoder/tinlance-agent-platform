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
