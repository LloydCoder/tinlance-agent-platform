# Tinlance Agent Platform

[![CI](https://github.com/LloydCoder/tinlance-agent-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/LloydCoder/tinlance-agent-platform/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.12--3.14-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

**Tinlance Agent Platform is a provider-neutral, governed execution and authority substrate for production-grade AI agents.**

It establishes **who may act, on whose behalf, with which capabilities, under which policy and approvals, within which budgets and tenant boundaries, and what evidence proves what happened**.

It is intentionally **not** an agent application, model provider, CRM, domain product, or operating system. It is the authority and execution layer beneath the **Tinlance Agentic OS**.

> **Core invariant:** **Intent is proposed by agents; authority is established by the platform; consequential actions are executed only at governed boundaries; evidence records what happened.**

---

## Why this platform exists

Modern agents can reason, retrieve information, call tools, delegate to other agents, maintain memory, and take consequential actions. That makes a normal application architecture insufficient: the model cannot be the source of authority.

Tinlance Agent Platform therefore separates **reasoning from authority**:

`Principal → Tenant → Capability → Policy → Approval → Execution Boundary → Evidence`

Model output, retrieved content, tool output, peer-agent messages, and external intelligence are treated as **untrusted data**. None can grant permission by itself.

This design reflects current agent-security guidance emphasizing least privilege, explicit tool authorization, human approval for high-impact actions, identity/authorization, isolation, auditability, and evaluation. See [NIST's AI Agent Standards Initiative](https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure), [NIST's agent identity and authorization work](https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd), and the [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html).

---

## What the platform provides

### Authority and control
- Explicit principal, agent, tenant, and execution identity.
- Deny-by-default authorization and complete mediation.
- Capability-based access without treating capability possession as sufficient authority.
- Policy decisions based on risk, reversibility, data classification, resource scope, and blast radius.
- Human approval for high-risk, irreversible, sensitive/restricted, or broad-blast-radius actions.
- Approval binding to tenant, run, action, resource, and expiry.
- Re-authorization immediately before consequential side effects.
- Child-agent delegation that cannot widen parent authority or change tenant.
- Hard budgets and bounded execution.

### Governed execution
- Deterministic runtime lifecycle and terminal-state integrity.
- Provider-neutral model gateway.
- Scoped tool and MCP gateway.
- Fail-closed sandbox boundary with command/path/network controls.
- Execution-only secret handles rather than normal model context.
- Resumable orchestration and handoff contracts.
- Tenant-scoped memory/context with trust and classification controls.
- Append-oriented evidence, events, audit records, and trajectory integrity.

### Assurance
- Correlated observability and security events.
- Deterministic safety/regression evaluation.
- PostgreSQL migrations with tenant RLS and cross-tenant integrity controls.
- Architecture/dependency-boundary tests.
- Agent OS API v1.1 contract tests, authenticated tenant binding, and bounded request-idempotency for consequential requests.
- Dependency auditing and SBOM generation.
- Immutable CI action references.
- Signed release artifacts through the release workflow.
- Conformance tests for the canonical authority path.

---

## Canonical architecture

```text
                           Tinlance Agentic OS
                  users · sessions · tasks · workflows
                                  │
                                  │ intent / lifecycle
                                  ▼
                    ┌─────────────────────────────┐
                    │   Tinlance Agent Platform   │
                    │                             │
                    │  Control plane              │
                    │  identity · tenancy         │
                    │  authorization · policy     │
                    │  approvals · budgets        │
                    │                             │
                    │  Execution plane             │
                    │  runtime · models · tools   │
                    │  MCP · sandbox · secrets    │
                    │  orchestration              │
                    │                             │
                    │  Evidence plane              │
                    │  context · memory · events  │
                    │  evidence · trajectory      │
                    │  observability · evaluation │
                    └──────────────┬──────────────┘
                                   │
                 ┌─────────────────┼─────────────────┐
                 ▼                 ▼                 ▼
          model providers    tools / MCP       isolated compute
                                   │
                                   ▼
                         external systems/data

     FAS / FAS-Bench / FDSE / TADS / ThreatFade / Hezqara / FusionOps
                              consume the platform
                         but are not platform dependencies
```

### Authority chain

`principal → tenant → capability → policy → approval → execution boundary → evidence`

The final execution boundary is the enforcement point. A successful model response, tool registration, retrieved document, or prior approval does not by itself authorize a side effect.


## R10 — Governed Execution Contract

The Platform publishes the versioned `governed-execution.v1` contract for consequential actions.

```text
Agent
  ↓
SDK
  ↓
authenticated identity
  ↓
tenant + agent binding
  ↓
capability + tool version
  ↓
policy
  ↓
approval (when required)
  ↓
budget + timeout
  ↓
sandbox / secret gates
  ↓
tools.execute
  ↓
evidence + audit
  ↓
execution result / outcome
```

Public R10 operations include:

- `tools.execute`
- `approvals.decide`
- `executions.get`

The contract enforces canonical intent fingerprints, tenant-scoped idempotency, approval binding and single-use consumption, explicit terminal/ambiguous outcomes, execution-bound evidence, correlated audit events, and fail-closed required-control failures.

See [R10 Governed Execution Contract](docs/R10-GOVERNED-EXECUTION.md) for the normative repository contract and the explicit distinction between reference implementations and production deployment adapters.

### Agent Platform vs Agentic OS

| Concern | Agent Platform | Tinlance Agentic OS |
|---|---|---|
| Identity and tenancy | **Owns** | Consumes |
| Authorization and policy | **Owns** | Requests |
| Approval authority | **Owns** | Presents/coordinates |
| Execution budgets | **Owns** | Consumes |
| Tool/MCP authorization | **Owns** | Discovers/uses |
| Sandbox boundary | **Owns** | Requests governed execution |
| Evidence and security events | **Owns** | Displays/consumes |
| User sessions | Platform run context | **Owns** |
| Tasks/workflows/apps | Platform execution contracts | **Owns** |
| Desktop/shell/system UX | Not core | **Owns** |
| Domain product logic | Not core | Integrates |

The separation is deliberate: the OS composes intent and lifecycle; the Platform establishes authority and executes consequential work.

---

## Security invariants

The following are architectural invariants, not suggestions:

1. **Tenant scope is immutable** across a governed request.
2. **Capability possession never bypasses policy.**
3. **Prohibited and secret-data actions cannot be approved into execution.**
4. **Every consequential tool call is re-authorized immediately before the side effect.**
5. **Approval is exact enough to prevent scope substitution or replay.**
6. **Child agents cannot widen parent authority or change tenant.**
7. **Untrusted content cannot silently become trusted instructions.**
8. **Secrets are execution-only handles and are excluded from ordinary context/trajectory.**
9. **Evidence is attributable and integrity-protected.**
10. **Evaluation results never grant runtime authority.**
11. **Security and audit telemetry must not require sensitive prompt/tool payloads.**
12. **Unavailable required isolation fails closed.**

These controls address the principal agent risks highlighted by OWASP, including excessive agency, tool abuse, prompt injection, memory poisoning, data exfiltration, approval manipulation, cascading multi-agent failures, denial-of-wallet, and sensitive-data exposure.

---

## Canonical M0–M14 roadmap

| Milestone | Capability | Canonical outcome |
|---|---|---|
| **M0** | Foundation | Contracts, kernel, package DAG, RLS, threat model |
| **M1** | Identity | Normalized principals, agent identity/versioning, tenant binding |
| **M2** | Authorization | Explicit capabilities, deny-by-default, complete mediation |
| **M3** | Approval | Resumable review, exact action binding, expiry |
| **M4** | Runtime | Fail-closed lifecycle, budgets, terminal-state integrity |
| **M5** | Model Gateway | Provider-neutral model port and usage validation |
| **M6** | Tool/MCP Gateway | Scoped tools, resource binding, transport isolation |
| **M7** | Sandbox | Isolated workspace and fail-closed command/path/network policy |
| **M8** | Orchestration | Agent runner, handoff/delegation, resumability |
| **M9** | Memory | Tenant-scoped context, trust/classification/redaction |
| **M10** | Evidence/Event | Append-oriented events/evidence and trajectory integrity |
| **M11** | Observability | Correlated traces, metrics, security events |
| **M12** | Evaluation | Deterministic safety/regression gates |
| **M13** | Domain SDK | Stable consumer/conformance surface |
| **M14** | Enterprise | Integrity, operations, supply chain, recovery, release gates |

**Important:** the roadmap describes platform capability boundaries, not a claim that every reference implementation is itself a hosted production service. The repository distinguishes implemented reference behavior from deployment infrastructure that must be supplied by operators.

See [docs/ROADMAP.md](docs/ROADMAP.md) for the authoritative milestone contract.

---

## Enterprise implementation posture

The repository deliberately distinguishes **platform implementation** from **production infrastructure**.

| Surface | In-repository implementation | Production deployment responsibility |
|---|---|---|
| Identity / authorization / approval | Governed reference implementations | Enterprise identity provider and durable policy storage |
| Runtime / orchestration | Deterministic reference path | Durable workers, queues, cancellation and recovery |
| Model / tool / MCP | Provider-neutral gateways | Approved providers and hardened external services |
| Sandbox | Fail-closed Linux/Bubblewrap adapter | Hardened host/supervisor and resource isolation |
| Memory / evidence / events | Tenant-scoped reference stores + SQL integrity | Durable repositories, retention and backup |
| Observability | Correlated contracts/sinks | OpenTelemetry collector, backend, alerting and retention |
| Evaluation | Deterministic regression runner | Release corpus, continuous evaluation operations |
| SDK | Stable domain registration surface | Consumer compatibility/conformance management |

A production deployment additionally requires durable PostgreSQL repositories, an external secret manager, isolated execution infrastructure, telemetry collection, backup/restore, incident response, operational controls, and provider-specific hardening.

**Enterprise-grade architecture does not mean pretending external infrastructure is already deployed.**

See [docs/ENTERPRISE-BASELINE.md](docs/ENTERPRISE-BASELINE.md) for the production acceptance checklist.

---

## Repository structure

```text
.
├── apps/                    # thin operational entry points
├── database/                # PostgreSQL migrations, RLS and integrity tests
├── docs/                    # architecture, roadmap, ADRs and status
├── evals/                   # evaluation corpus and methodology
├── packages/                # bounded platform capabilities
├── security/                # threat models and security material
├── tests/                   # unit, architecture, conformance and security
├── AGENTS.md                # repository agent/development contract
├── ARCHITECTURE.md          # architectural boundary
├── CONTRIBUTING.md          # contribution rules
├── LICENSE                  # Apache-2.0 license
├── README.md                # repository entry point
└── SECURITY.md              # vulnerability/security policy
```

### Dependency direction

`contracts → kernel → services → adapters → apps`

Core contracts/kernel packages remain provider/framework neutral. Provider SDKs, web frameworks, and domain repositories must not leak into the authority kernel. New cross-boundary dependencies require architectural justification.

---

## Verification and quality gates

CI currently validates:

- Python **3.12, 3.13 and 3.14**.
- Dependency installation and `pip check`.
- Python compilation.
- Ruff lint and formatting.
- Strict mypy.
- Pytest with an **85% minimum package coverage gate**.
- Dependency vulnerability auditing with `pip-audit`.
- CycloneDX SBOM generation.
- PostgreSQL migration, RLS and integrity tests.
- Architecture/dependency-boundary checks.

The release workflow additionally builds distributions, generates an SBOM, signs release artifacts with Sigstore, and creates the GitHub release.

### Local verification

```bash
python -m pip install -e ".[test,security]"
python -m pip check
ruff check .
ruff format --check .
mypy packages
pytest --cov=packages --cov-report=term-missing --cov-fail-under=85
```

For the database gates, run the SQL migrations and tests against a PostgreSQL instance matching the CI configuration.

---

## Integration model

Domain systems should consume the platform through contracts and the SDK rather than importing internal authority implementation.

Current and planned Tinlance consumers include:

- **FAS / FAS-Bench** — security reasoning and evaluation.
- **FDSE** — governed domain engineering semantics and execution.
- **TADS / ReconOS** — target/world intelligence.
- **ThreatFade** — security-domain workload.
- **Hezqara** — healthcare operations workload.
- **FusionOps** — operations workload.
- **Tinlance Agentic OS** — higher-level agent-native operating environment.

The platform remains independent from all of them.

---

## Design principles

### 1. Authority outside the model

The model can propose. It cannot authorize itself.

### 2. Complete mediation

Authorization is checked at the point where a consequential side effect occurs, not only when an agent plans it.

### 3. Least privilege

Every execution path is scoped to the smallest useful tenant, capability, resource, budget and trust boundary.

### 4. Fail closed

Missing policy, invalid identity, expired approval, unavailable isolation, malformed scope, or security-control failure must not silently become permission.

### 5. Evidence over assertion

The platform distinguishes observation, evidence, event, trajectory, decision and execution outcome. A model's statement about what happened is not proof that it happened.

### 6. Provider neutrality

The authority kernel should not become coupled to a single model vendor, tool vendor, MCP implementation, database framework, or cloud.

### 7. Domain independence

Domain intelligence is an input to governed execution, never an implicit authority source.

### 8. Human accountability

Human approval remains a control for high-impact operations; it is not replaced by model confidence or an automated risk score.

---

## Documentation map

| Document | Purpose |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | System boundary, planes, authority chain and invariants |
| [docs/architecture/agent-platform-agent-os-integration.md](docs/architecture/agent-platform-agent-os-integration.md) | Canonical Agent OS integration contract and API v1.1 boundary |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Canonical M0–M14 milestone definition |
| [docs/ENTERPRISE-BASELINE.md](docs/ENTERPRISE-BASELINE.md) | Enterprise controls and production acceptance |
| [SECURITY.md](SECURITY.md) | Security policy and vulnerability handling |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution and architectural rules |
| [security/](security/) | Threat models and security analysis |
| [tests/](tests/) | Executable assurance |
| [database/](database/) | Persistence, RLS and integrity controls |

Historical status/ADR documents are retained for traceability. Where a historical milestone label conflicts with the canonical sequence, **docs/ROADMAP.md and the current implementation are authoritative**.

---

## Scope: what this repository is and is not

### This repository is

- A governed execution and authority substrate.
- A provider-neutral control/execution/evidence layer.
- A security boundary for agentic side effects.
- A reusable foundation for Tinlance and external domain applications.
- A reference implementation plus contracts that can be hardened into production deployments.

### This repository is not

- The Tinlance Agentic OS.
- A general-purpose LLM framework.
- A model provider.
- A generic MCP server collection.
- A CRM, ERP, EHR, SOC, scanner, or domain product.
- FAS, FDSE, TADS, ThreatFade, Hezqara, ReconOS or FusionOps.
- A claim that external production infrastructure is already deployed.

---

## License

Tinlance Agent Platform is released under the **Apache License 2.0**. See [LICENSE](LICENSE).

Copyright © 2024–2026 Tinlance Limited.

---

## Status

The repository's canonical M0–M14 architecture, contracts, reference implementations, security controls, tests, documentation and release gates are maintained as one system.

For production use, complete the deployment acceptance controls in [docs/ENTERPRISE-BASELINE.md](docs/ENTERPRISE-BASELINE.md) and independently validate the infrastructure surrounding the platform.

**Tinlance Agent Platform establishes authority. Agentic applications use that authority. Evidence proves what happened.**
