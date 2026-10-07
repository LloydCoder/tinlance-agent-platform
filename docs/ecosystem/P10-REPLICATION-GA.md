# P10 — Replication & Agent System GA

The Platform is the sole authority plane for P10. Replication proves that independent enterprises can use the same governed substrate without duplicating authority.

## Contract

Two independent tenants must traverse the same identity, tenancy, authorization, policy, approval, budget, sandbox, secret, execution, evidence and audit boundaries.

## Mandatory security invariants

1. Tenant binding is immutable.
2. A capability declaration never grants authority.
3. Replica A cannot execute against Replica B resources.
4. Approval is bound to the exact tenant/run/action/resource intent.
5. Budgets and quotas are tenant-scoped and cannot be transferred by replication.
6. Secrets are execution-scoped and tenant-scoped.
7. Evidence and audit records cannot cross tenant boundaries.
8. Delegation cannot widen authority or change tenant.
9. Model output, memory, tool/MCP output and remote-agent messages remain untrusted data.
10. Replication changes parameters, not Platform authorization semantics.

## Exit gate

P10 is complete for the Platform only when tenant-isolation, authorization, approval, budget, evidence and runtime tests are green, all repository/security workflows are green, and the ecosystem replication manifest matches the reviewed four-repository lock.

External customer deployment and independent certification remain external assurance activities.
