# Tinlance Agent Platform Architecture

Agent Platform is Tinlance's generic governed execution substrate, separate from Agentic OS and domain products.

## Planes
- Control: identity, tenancy, authorization, policy, approvals, budgets, registries.
- Execution: runtime, orchestration, model/tool gateways, secrets and sandbox adapters.
- Evidence: events, trajectory, provenance, audit, observability and evaluation.

## Dependency DAG
contracts -> kernel -> services -> adapters -> apps

Adapters depend inward. The reverse direction is forbidden.

## M0 packages
- contracts: provider-neutral vocabulary/value objects
- kernel: security invariants with no provider/framework dependency
- identity: principal validation
- tenancy: tenant propagation rules
- authorization: deterministic deny-by-default capability checks
- policy: deterministic risk policy boundary

Runtime, durable workflow, gateways, sandbox implementations and persistence services are later milestones; interfaces alone are not implementations.

Domain repositories consume stable platform contracts and the platform never imports them.
