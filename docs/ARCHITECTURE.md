# Architecture

## System boundary

Tinlance Agent Platform is the governed execution substrate beneath Tinlance Agentic OS. It is domain-neutral and must not import FDSE, FAS, FAS-Bench, TADS, ReconOS, ThreatFade, Hezqara or FusionOps.

The platform establishes authority outside model reasoning and re-checks it at the final side-effect boundary.

## Planes

- **Control plane:** identity, tenancy, authorization, policy, approvals, agents and budgets.
- **Execution plane:** runtime, model gateway, tool/MCP gateway, sandbox, secrets and orchestration.
- **Evidence plane:** context/memory, events, evidence, trajectory, observability and evaluation.

## Dependency direction

`contracts -> kernel -> services -> adapters -> apps`.

Contracts and kernel are provider/framework neutral. Domain products consume the SDK; they never become platform dependencies.

## Authority chain

`principal -> tenant -> capability -> policy -> approval -> execution boundary -> evidence`.

Model output, tool output, retrieved content and peer-agent messages are untrusted data. They cannot create authority.

## Canonical milestones

| Milestone | Required boundary | Primary evidence |
|---|---|---|
| M0 | foundation, package DAG, RLS, threat model | architecture + SQL + boundary tests |
| M1 | identity | normalized principal/agent contracts |
| M2 | authorization | deny-by-default + complete mediation |
| M3 | approval | exact action binding + expiry |
| M4 | runtime | terminal-state and budget invariants |
| M5 | model gateway | provider-neutral validated usage |
| M6 | tool/MCP | scoped registration + tenant/capability binding |
| M7 | sandbox | fail-closed isolation and path/command policy |
| M8 | orchestration | tenant-safe runner/delegation |
| M9 | memory | trust/classification/redaction |
| M10 | evidence/event | append-only evidence and tamper-evident trajectory |
| M11 | observability | correlated trace/metric/security signals |
| M12 | evaluation | deterministic safety regression gates |
| M13 | domain SDK | stable consumer surface |
| M14 | enterprise | integrity, release, supply-chain and operational gates |

## Production boundary

The repository provides contracts and reference implementations. Production deployment additionally requires durable PostgreSQL repositories, external secret management, approved provider adapters, isolated execution infrastructure, telemetry collection, backup/restore, incident response and operational controls. These are deployment responsibilities, not authority logic.

## Security invariants

1. Tenant identifiers are immutable across a request.
2. Capability possession does not bypass policy.
3. Prohibited and secret-data actions cannot be approved into execution.
4. Every consequential tool call is re-authorized immediately before execution.
5. Approval binds tenant, run, action and resource.
6. Child agents cannot widen parent authority or change tenant.
7. Untrusted content is not silently promoted to trusted context.
8. Secrets are execution-only handles.
9. Evidence is attributable and content-addressed.
10. Evaluation results never grant authority.
