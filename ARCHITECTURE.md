# Tinlance Agent Platform Architecture

Agent Platform is Tinlance's generic governed execution substrate, separate from Agentic OS and domain products.

## Planes
- Control: identity, tenancy, authorization, policy, approvals, budgets, registries.
- Execution: runtime, orchestration, model/tool gateways, secrets and sandbox adapters.
- Evidence: events, trajectory, provenance, audit, observability and evaluation.

## Dependency DAG
contracts -> kernel -> services -> domain -> adapters -> apps

Adapters depend inward. The reverse direction is forbidden.

## M0 packages
contracts, kernel, identity, tenancy, authorization and policy establish authority and tenant invariants.

## M1 packages
- domain: tenant-owned durable entities and lifecycle rules.
- persistence: repository ports plus deterministic in-memory implementation for contract tests.
- sandbox: versioned execution boundary and Docker adapter.

PostgreSQL is the durable M1 store; tenant RLS is defense in depth. Domain products consume contracts and never import domain-specific product code into the platform.

## Security invariant
Capability does not imply authority; model output never grants authority; every consequential execution must be attributable to a tenant and actor and pass the policy/approval boundary.