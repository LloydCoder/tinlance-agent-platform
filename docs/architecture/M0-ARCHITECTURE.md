# M0 Architecture Baseline

## Scope

M0 establishes the platform kernel boundary. It does not implement model providers, tools, durable workflows, sandboxing, or domain capabilities.

## Control flow invariant

```text
principal
  -> request context
  -> task intent
  -> capability request
  -> authorization
  -> policy decision
  -> risk evaluation
  -> approval decision
  -> execution adapter
  -> observation
  -> evidence / audit / telemetry
```

No agent may invoke an external side effect directly.

## Planes

### Control plane

Identity, tenancy, agent registry, policy, authorization, approvals, budgets, capability registry, tool/model registries, emergency controls.

### Execution plane

Disposable workers, agent runtime, orchestration, model calls, tool calls, sandboxed workloads and browser sessions.

### Evidence plane

Events, trajectories, provenance, audit records, evaluation results and observability.

The execution plane must not gain implicit control-plane authority merely by compromising a worker.

## Layering

1. Infrastructure
2. Identity and security
3. Authorization and policy
4. Runtime and execution
5. Context, memory and knowledge
6. Models, tools and skills
7. Orchestration
8. Evidence, trajectory and observability
9. Agents
10. Domains
11. Applications

Lower layers cannot import domain-specific code from higher layers.

## M0 technology decisions

- **Language:** Python 3.12.
- **Core style:** modular monolith first; explicit ports/adapters.
- **Durable store:** PostgreSQL.
- **Tenant isolation:** application authorization plus PostgreSQL RLS for tenant-owned data.
- **Events:** transactional outbox and PostgreSQL-backed durable events before introducing Kafka/NATS.
- **API:** FastAPI at the application edge only.
- **Telemetry:** OpenTelemetry-compatible interfaces; content is opt-in and redacted.
- **Model runtime:** provider adapters behind a platform-owned gateway.
- **Policy:** policy interface first; deterministic enforcement outside model reasoning. A policy engine dependency will be selected in M2 after comparative evaluation.
- **Workflow:** durable workflow port first; no premature external workflow vendor dependency.
- **Sandbox:** workload-risk decision in M7; containers are not assumed to be sufficient for hostile workloads.

## Explicit non-decisions

Kubernetes, Kafka, graph databases, service meshes, dedicated workflow vendors, and a single model provider are not architectural requirements at M0. Each must earn adoption through measurable operational need.

## Domain boundary

FDSE, TADS, ThreatFade, ReconOS, FadeReach and future domains register capabilities against stable platform contracts. They do not own identity, authorization, policy, audit, generic runtime, or generic tool/model gateways.
