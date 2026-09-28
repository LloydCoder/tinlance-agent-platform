# Architecture

## System boundary

Tinlance Agent Platform is the governed execution and authority substrate beneath Tinlance Agentic OS.

It is **domain-neutral** and must not import or become dependent on FAS, FAS-Bench, FDSE, TADS, ReconOS, ThreatFade, Hezqara or FusionOps.

The platform establishes authority outside model reasoning and re-checks authorization at the final consequential side-effect boundary.

## Planes

### Control plane
Identity, tenancy, authorization, policy, approvals, agents and budgets.

### Execution plane
Runtime, model gateway, tool/MCP gateway, sandbox, secrets and orchestration.

### Evidence plane
Context/memory, events, evidence, trajectory, observability and evaluation.

## Authority chain

`principal → tenant → capability → policy → approval → execution boundary → evidence`

This chain is the central platform invariant.

Model output, tool output, retrieved content, external intelligence and peer-agent messages are **untrusted data**. They may inform a decision but cannot create authority.

## Dependency direction

`contracts → kernel → services → adapters → apps`

Contracts and kernel remain provider/framework neutral. Provider-specific adapters sit at the edge. Domain consumers use public contracts/SDK surfaces.

## Canonical milestones

| Milestone | Required boundary | Primary evidence |
|---|---|---|
| M0 | Foundation, package DAG, RLS, threat model | Architecture + SQL + boundary tests |
| M1 | Identity | Principal/agent/tenant contracts |
| M2 | Authorization | Deny-by-default + complete mediation |
| M3 | Approval | Exact action binding + expiry |
| M4 | Runtime | Terminal-state + budget invariants |
| M5 | Model gateway | Provider-neutral validated usage |
| M6 | Tool/MCP | Scoped registration + tenant/capability binding |
| M7 | Sandbox | Fail-closed isolation and policy |
| M8 | Orchestration | Tenant-safe runner/delegation |
| M9 | Memory | Trust/classification/redaction |
| M10 | Evidence/event | Append-oriented evidence + trajectory integrity |
| M11 | Observability | Correlated trace/metric/security signals |
| M12 | Evaluation | Deterministic safety regression gates |
| M13 | Domain SDK | Stable consumer surface |
| M14 | Enterprise | Integrity, release, supply-chain and operational gates |

The canonical definitions live in [docs/ROADMAP.md](docs/ROADMAP.md).

## Platform vs Agentic OS

**Agent Platform owns:** identity, tenancy, authorization, policy, approval authority, budgets, governed execution, sandbox/security boundaries, evidence and security events.

**Agentic OS owns:** users, sessions, tasks, workflows, agent applications, presentation, system integration and higher-level lifecycle.

The OS composes intent and lifecycle. The Platform establishes authority and executes consequential work.

## Production boundary

The repository provides contracts and reference implementations. A production deployment additionally requires durable PostgreSQL repositories, external secret management, approved model/tool providers, isolated execution infrastructure, telemetry collection, backup/restore, incident response and operational controls.

Those deployment responsibilities must not be mistaken for authority logic embedded in the platform.

## Security invariants

1. Tenant identifiers are immutable across a governed request.
2. Capability possession cannot bypass policy.
3. Prohibited and secret-data actions cannot be approved into execution.
4. Every consequential tool call is re-authorized immediately before execution.
5. Approval binds tenant, run, action and resource and expires.
6. Child agents cannot widen parent authority or change tenant.
7. Untrusted content is not silently promoted to trusted context.
8. Secrets are execution-only handles.
9. Evidence is attributable and integrity-protected.
10. Evaluation results never grant authority.
11. Required isolation failures fail closed.
12. Security telemetry does not require sensitive payload capture.

## Design references

The architecture is consistent with current external guidance on agent identity/authorization, least privilege, high-impact approvals, isolation, observability and evaluation. External guidance informs the design; repository tests and contracts remain the implementation authority.
