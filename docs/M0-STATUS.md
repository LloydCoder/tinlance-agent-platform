# M0 Status

M0 is complete as a **foundation milestone**, not as a production-ready autonomous-agent platform.

## Delivered

- bounded package structure replacing `packages/common`
- provider-neutral security contracts
- tenant-consistent immutable request context
- kernel authority invariants
- identity and child-tenant validation
- deterministic deny-by-default authorization
- deterministic risk policy decisions
- executable architecture boundary tests
- PostgreSQL control-plane migrations
- executable tenant RLS isolation test
- Python lint, format, type and unit-test gates
- dependency review and Dependabot configuration
- security and contributor guidance

## Explicitly deferred

Runtime execution, durable workflow, model gateway, tool gateway, approvals, secrets broker, sandbox runtime, event/outbox implementation, trajectory/evidence persistence, observability implementation, evaluation harness, SDK packaging and production deployment remain later milestones.

These are deliberate milestone boundaries, not hidden implementations.

## Readiness

M0: **FOUNDATION COMPLETE**

Production readiness: **NOT CLAIMED**.
