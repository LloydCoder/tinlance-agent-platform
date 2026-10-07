# P6 — Production Runtime Readiness Contract

P6 closes the repository-side production runtime contract without pretending that repository code is itself a deployed production environment.

## Repository-owned primitives

The Platform repository owns the execution semantics for:

- durable execution state;
- leases and crash recovery;
- outbox/event publication;
- idempotency and replay controls;
- authoritative evidence and audit;
- observability and incident correlation;
- release and recovery gates.

## Deployment-owned infrastructure

A production installation must separately provide and evidence:

- PostgreSQL or an equivalent durable transactional store;
- a durable queue/worker substrate;
- object/blob storage for large artifacts;
- external KMS/secret management;
- isolated sandbox workers;
- telemetry/metrics/logging backends;
- backup/restore and disaster-recovery procedures;
- regional/network failure handling;
- operational incident response.

These are deliberately not hidden inside the authority kernel.

## Failure model

Production acceptance must test:

1. worker crash during a governed run;
2. duplicate queue delivery;
3. database transaction retry;
4. lease expiry and takeover;
5. outbox replay;
6. network partition;
7. restored database/object state;
8. rollback after partial execution;
9. regional capacity loss;
10. evidence continuity after recovery.

A recovery mechanism may resume or block execution, but it cannot grant authority.

## Exit criterion

P6 repository completion means the durable semantics, recovery invariants, deployment contract and failure model are executable/documented and CI-certified. Production completion additionally requires external infrastructure and DR evidence.
