# ADR-016: Durable workspace leases and fencing

- **Status:** Proposed — W5 implementation in progress
- **Date:** 2026-11-08
- **Decision owners:** Tinlance Agent Platform maintainers
- **Related:** ADR-015, TSIC issue #102, W5 persistent-computer acceptance

## Context

The browser workspace currently uses a process-local file lock to prevent two local processes from opening the same profile concurrently. The durability package also contains an in-memory `WorkLeaseStore`. Neither is a distributed authority: both lose their state across host/process failure and cannot revoke a stale worker across replicas.

W5 requires lease renewal, expiry, revocation, stale-worker fencing, quota continuity and auditable recovery across restarts. A lease must not be reclaimed merely because an old process appears unresponsive.

## Decision

Introduce a tenant-scoped PostgreSQL workspace lease authority:

1. One current lease row per `(tenant_id, workspace_id)`.
2. Every acquisition has a unique lease ID, owner subject, worker identity, expiry and monotonically increasing fencing token.
3. Acquisition is serialized by a row lock. An unexpired active lease cannot be duplicated.
4. Reacquisition after expiry, revocation or release increments the fencing token. The prior worker's token is permanently stale.
5. Renewal requires the exact lease ID and current fencing token and fails after expiry or revocation.
6. Revocation and release are explicit state transitions; neither silently transfers ownership.
7. Acquire, renew, expire, revoke and release append immutable tenant-scoped events.
8. Both current-state and event tables use forced row-level security. The event table is protected by both privileges and mutation-rejection triggers.
9. Each adapter operation owns a short transaction and sets `platform.tenant_id` transaction-locally.

The process-local `WorkLeaseStore` remains a reference/test implementation and is not a production lease authority.

## Consequences and required integration

- Every consequential workspace command must verify the current fencing token at the supervisor boundary. Merely checking a lease once at process startup is insufficient.
- On lease loss, the trusted supervisor must stop and reap the old worker, close its browser context, and prevent further host-side effects.
- Quota reservations remain separately governed by the durable quota ledger. Workspace lease revocation must not silently refund quota or resolve an uncertain side effect.
- Profile durability, encryption-at-rest, backup/restore and host-loss recovery are not established by this lease store; W6 and production review remain separate gates.
- A real continuous eight-hour soak on a controlled persistent host is required. Simulated time and segmented hosted jobs are not acceptable substitutes.

## Alternatives considered

- **Process-local `flock`:** useful for one-host profile exclusivity, but does not provide cross-host ownership or fencing.
- **In-memory `WorkLeaseStore`:** suitable for reference semantics only; lost on restart.
- **Lease expiry without fencing:** rejected because an old worker may continue after a new owner has acquired the workspace.
- **Automatic quota release on lease expiry:** rejected because the old worker may have completed a consequential side effect before crashing.

## Acceptance evidence

W5 requires SQL integration evidence for concurrent acquisition denial, renewal, explicit revocation, stale-token rejection, expiry/reacquisition, append-only audit continuity and forced RLS. It also requires a continuous eight-hour host soak with real browser/profile state, worker/supervisor restarts, quota behavior, recovery and teardown. No production certification is implied by CI feasibility artifacts.
