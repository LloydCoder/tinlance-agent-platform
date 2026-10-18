# P8 — Budgets, Quotas, Capacity and Cost Enforcement

**Canonical ecosystem phase:** P8. The canonical definition is owned by
`tinlance-agent-developer/docs/ecosystem/PHASE-MATRIX.md`; this document
describes the Platform implementation and does not redefine P8.

## Authority boundary

Agent Platform is the sole authority for admission, budget reservation,
settlement, quotas, capacity gates and cost evidence. OS may request work and
surface usage; SDK may transport typed requests/results; neither may bypass or
reimplement Platform admission policy.

## Existing enterprise controls

Tenant identity and tenancy isolation, principal/workspace context, policy
evaluation, approval requirements and approval expiry remain governed by the
existing Platform authority contracts. P8 consumes those controls; it does not
replace them or let a quota reservation satisfy an approval requirement.

## Repository implementation

- `packages/budgets`: deterministic in-memory reference budgets and quotas.
- `packages/budgets/.../postgres_quota.py`: transaction-bound adapter for
  persistent reservation, settlement and release procedures.
- `database/migrations/010_p8_budget_quota_ledger.sql`: tenant and
  organization limits, reservation state, append-only cost ledger, RLS and
  transactional SQL procedures.
- `database/migrations/011_p8_quota_reservation_recovery.sql`: bounded
  reservation leases and explicit reconciliation markers for expired work.
  Expiry is never treated as proof that a consequential side effect did not occur.
- `tests/test_m13_4_budget_governance.py` and
  `tests/test_p8_budget_quota_ledger.py`: scope binding, in-process race
  controls, replay/idempotency, capacity envelopes, finite-value validation
  and adapter transaction ownership.
- `database/tests/006_p8_quota_ledger.sql`,
  `database/tests/007_p8_quota_concurrency.sql`, and
  `database/tests/008_p8_quota_recovery.sql`: PostgreSQL reservation,
  settlement, release, append-only evidence, tenant/organization concurrent
  admission and expired-lease reconciliation checks.

## Required semantics

1. Admission locks the tenant budget row and, when present, the organization
   budget row in a consistent order before checking reserved plus consumed
   usage. Concurrent reservations cannot oversubscribe those rows.
2. Idempotency keys are tenant-scoped. Replays must preserve the complete
   reservation intent; changed scope or dimensions are rejected.
3. Concurrency is an in-flight gauge. Settlement releases concurrency while
   charging actual tool calls, tokens and cost.
4. Settlement requires a bounded `measurement_ref` and is idempotent for
   identical actual usage. Conflicting replays fail closed. Cost is normalized
   to the ledger's six-decimal numeric scale before comparison or charging.
   A usage overrun is recorded as `overrun`, charged to the ledger and
   returned explicitly so the caller stops further work.
5. Release is permitted only for an un-settled reservation and requires a
   normalized reason. Cancellation after a consequential side effect must
   settle observed usage rather than pretend it was refunded. Once recovery
   has been requested for an expired lease, release is blocked; reconciliation
   must settle measured usage (zero only with an explicit measurement reference).
6. Partial settlement charges measured usage and releases the unused estimate.
   A release before side effects charges zero; a post-side-effect cancellation
   is not automatically refundable.
7. Cost evidence is append-only and bounded to allow-listed identifier
   metadata. Trace identifiers are format-validated; prompts, arbitrary
   provider bodies, credentials and secrets are not ledger evidence. Lease
   renewals and recovery requests are separately recorded in the ledger.
8. All database calls participate in the caller's tenant-scoped transaction.
   Domain state, reservation transition and ledger entry must commit or roll
   back together. The adapter does not commit or close caller-owned connections.
9. RLS and composite tenant foreign keys prevent cross-tenant access and
   cross-tenant agent/run/organization binding.
10. Capacity gates compare measured throughput, p95/p99 latency and concurrency
    to the declared envelope. Non-finite or negative measurements/limits fail
    closed; maximum concurrency must be positive, while zero usage budgets are
    valid deny-all limits.

## Production boundary

The in-memory quota implementation is a reference/test implementation only.
The PostgreSQL adapter requires migrations 010 and 011 to be applied and
invoked inside a real tenant-scoped transaction. This repository change does **not** prove
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
