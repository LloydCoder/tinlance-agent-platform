# Tinlance Agent Platform

Tinlance's provider-neutral, governed agent execution substrate. It is not the Tinlance Agentic OS. The Agentic OS is a higher-level human/agent/organization environment; this repository supplies the governed execution primitives underneath it.

## Canonical architecture

FAS / FAS-Bench -> FDSE / domain products -> Tinlance Agent Platform -> Tinlance Agentic OS

Domain consumers include FDSE, TADS, ReconOS, ThreatFade, Hezqara and FusionOps. The platform never imports those products.

## Enterprise invariant

Agent -> Action -> Authority -> Evidence

Model output, tool output, retrieved content and peer-agent messages are untrusted. Authority is established outside model reasoning and re-authorized at the execution boundary. Tenant context cannot widen authority. Prohibited actions are never executable, including through approval. Every consequential side effect must be attributable, policy-mediated, budgeted and observable.

Secrets are execution-only handles and are not normal model context or trajectory data.

## Canonical M0-M14 sequence

| Milestone | Capability |
|---|---|
| M0 | Foundation |
| M1 | Identity |
| M2 | Authorization |
| M3 | Approval |
| M4 | Runtime |
| M5 | Model Gateway |
| M6 | Tool/MCP Gateway |
| M7 | Sandbox |
| M8 | Orchestration |
| M9 | Memory |
| M10 | Evidence/Event |
| M11 | Observability |
| M12 | Evaluation |
| M13 | Domain SDK |
| M14 | Enterprise |

Internal package/migration milestone labels may differ because implementation was built incrementally; the canonical product sequence is defined in docs/ROADMAP.md.

## Security model

- Identity is explicit and normalized.
- Authorization is deterministic and deny-by-default.
- Policy evaluates risk, reversibility, data classification and blast radius.
- High-risk, irreversible, sensitive/restricted and non-single-resource actions require approval.
- Prohibited and secret-data capabilities are denied.
- Approvals are tenant/run/action/resource bound and expire.
- Tool execution re-checks authorization and approval immediately before the side effect.
- MCP transport receives the governed tenant scope; it cannot silently drop tenancy.
- Sandbox requests require an isolated workspace and allowlisted commands/paths; unavailable isolation fails closed.
- Context excludes untrusted content by default and redacts common secret material.
- Evidence/trajectory/audit records are designed as append-only evidence surfaces.
- Database rows use tenant RLS plus cross-tenant composite foreign keys.
- Security events carry actor/trace/outcome metadata without requiring sensitive payloads.

These controls align with current agent security guidance emphasizing least privilege, tool-level approvals, isolation, tracing/evaluation and protection against excessive agency and prompt injection. See the references in docs/ENTERPRISE-BASELINE.md.

## Enterprise implementation status

The canonical M0-M14 sequence is backed by executable conformance tests. Each milestone may expose a provider-neutral contract/reference implementation rather than a cloud-specific production adapter. Production adapters remain intentionally outside the authority kernel.

| Surface | Repository implementation | Production responsibility |
|---|---|---|
| Identity / authorization / approval | governed reference implementation | identity provider and durable policy store |
| Runtime / orchestration | deterministic reference implementation | durable workers, queues and cancellation infrastructure |
| Model / tool / MCP | provider-neutral gateways | approved providers and hardened external services |
| Sandbox | fail-closed Bubblewrap adapter | hardened Linux host/supervisor |
| Memory / evidence / events | tenant-scoped in-memory reference stores + SQL integrity controls | durable repositories and retention controls |
| Observability | correlated in-memory sink/contracts | OpenTelemetry collector/backend and alerting |
| Evaluation | deterministic regression runner | release corpus and continuous evaluation operations |
| SDK | stable domain registration surface | consumer compatibility/conformance |

See [ARCHITECTURE](ARCHITECTURE.md), [ROADMAP](ROADMAP.md), [ENTERPRISE-BASELINE](ENTERPRISE-BASELINE.md) and the milestone threat models under `security/`.

## Repository structure

apps/ = thin operational entry points
database/ = migrations and RLS/integrity tests
docs/ = roadmap, status, ADRs and architecture
evals/ = evaluation corpus and methodology
packages/ = bounded platform capabilities
tests/ = unit, architecture, conformance and security
security/ = threat models

The dependency rule is executable: contracts -> kernel -> services -> adapters -> apps. Core packages cannot import provider SDKs, web frameworks or domain repositories.

## Production posture

The repository contains working provider-neutral implementations and a fail-closed Linux sandbox adapter. It does not pretend that an in-memory store is a production database or that a reference sandbox is a complete production deployment. Durable production deployment must supply the documented PostgreSQL, secret manager, telemetry, provider adapters, backup/restore, incident response and isolated execution infrastructure.

## Verification

CI runs Python 3.12-3.14, Ruff lint/format, mypy, pytest with an 85% minimum package-coverage gate, PostgreSQL migrations/RLS/integrity tests and architecture dependency checks. Tagged releases are built and Sigstore-signed by a dedicated release workflow. Every milestone requires implementation, tests, security validation and documentation.

## Relationship to Tinlance

FAS/FAS-Bench remain independent security reasoning/evaluation systems. FDSE consumes generic platform primitives. TADS/ReconOS remain world-intelligence products whose intelligence never becomes authority automatically. ThreatFade, Hezqara and FusionOps are domain workloads. Agentic OS sits above this substrate and composes people, agents, workflows, products and organizational operations.
