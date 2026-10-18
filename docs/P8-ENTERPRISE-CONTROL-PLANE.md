# P8 — Budgets, Quotas, Capacity and Cost Enforcement

**Canonical ecosystem phase:** P8. The canonical definition is owned by
`tinlance-agent-developer/docs/ecosystem/PHASE-MATRIX.md`; this document
describes the Platform implementation and does not redefine P8.

## Authority boundary

Agent Platform is the sole authority for admission, budget reservation,
settlement, quotas, capacity gates and cost evidence. OS may request work and
surface usage; SDK may transport typed requests/results; neither may bypass or
reimplement Platform admission policy.

## Repository implementation

- `packages/budgets`: deterministic in-memory reference budgets and quotas.
- `packages/budgets/.../postgres_quota.py`: transaction-bound adapter for
  persistent reservation, settlement and release procedures.
- `database/migrations/010_p8_budget_quota_ledger.sql`: tenant and
  organization limits, reservation state, append-only cost ledger, RLS and
  transactional SQL procedures.
- `tests/test_m13_4_budget_governance.py` and
  `tests/test_p8_budget_quota_ledger.py`: scope binding, concurrency races,
  replay/idempotency, capacity envelopes, finite-value validation and adapter
  transaction ownership.

## Required semantics

1. Admission locks the tenant budget row and, when present, the organization
   budget row in a consistent order before checking reserved plus consumed
   usage. Concurrent reservations cannot oversubscribe those rows.
2. Idempotency keys are tenant-scoped. Replays must preserve the complete
   reservation intent; changed scope or dimensions are rejected.
3. Concurrency is an in-flight gauge. Settlement releases concurrency while
   charging actual tool calls, tokens and cost.
4. Settlement is idempotent for identical actual usage. Conflicting replays
   fail closed. A usage overrun is recorded as `overrun`, charged to the
   ledger and returned explicitly so the caller stops further work.
5. Release is permitted only for an un-settled reservation and requires a
   normalized reason. Cancellation after a consequential side effect must
   settle observed usage rather than pretend it was refunded.
6. Partial settlement charges measured usage and releases the unused estimate.
   A release before side effects charges zero; a post-side-effect cancellation
   is not automatically refundable.
7. Cost evidence is append-only and bounded to allow-listed scalar metadata.
   Prompts, arbitrary provider bodies, credentials and secrets are not ledger
   evidence.
8. All database calls participate in the caller's tenant-scoped transaction.
   Domain state, reservation transition and ledger entry must commit or roll
   back together. The adapter does not commit or close caller-owned connections.
9. RLS and composite tenant foreign keys prevent cross-tenant access and
   cross-tenant agent/run/organization binding.
10. Capacity gates compare measured throughput, p95/p99 latency and concurrency
    to the declared envelope. Invalid, NaN, infinite and non-positive limits
    fail closed.

## Production boundary

The in-memory quota implementation is a reference/test implementation only.
The PostgreSQL adapter requires migration 010 to be applied and invoked inside
a real tenant-scoped transaction. This repository change does **not** prove
that a production database, migration pipeline, runtime database role, secret
manager, multi-region failover, or production telemetry has been deployed.
Those require environment-level evidence and load/failure testing.

## P8 exit gate

- [ ] SQL migration validates against the supported PostgreSQL version.
- [ ] Tenant and organization reservation races are tested against PostgreSQL,
  not only a mocked connection or in-process lock.
- [ ] RLS, role grants, idempotency conflicts, settlement replay, overrun,
  release/refund and crash/restart recovery pass integration tests.
- [ ] Budget/capacity finite-value and boundary tests pass.
- [ ] SDK and OS preserve the typed budget decision and do not grant authority.
- [ ] Cost ledger evidence is append-only and redacted/allow-listed.
- [ ] Exact-SHA ecosystem conformance, CI, security and post-merge audit pass.

Repository unit tests alone do not satisfy the PostgreSQL integration or
external production deployment requirements above.
