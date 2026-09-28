# M1 Status

M1 establishes a durable, tenant-isolated domain and the first governed execution boundary.

## Delivered
- Customer -> Project -> Repository -> Assessment -> Finding/Evidence ancestry.
- Explicit lifecycle state machines with invalid transitions rejected.
- Tenant-bound composite foreign keys.
- Tenant-scoped idempotency for assessments.
- PostgreSQL persistence schema and RLS.
- Transaction-local tenant context in integration tests.
- Versioned execution contract v1.
- Explicit approval reference for elevated-risk execution.
- Resource/time/pid/memory controls.
- Docker baseline sandbox with network-off default, read-only root, dropped capabilities, no-new-privileges and allowlisted environment.
- Fail-closed behavior when Docker is unavailable or execution times out.
- Integration tests for tenant isolation and sandbox network/timeout controls.

## Security boundary
The sandbox is a baseline adapter, not a claim of universal isolation. Host kernel/runtime configuration remains part of the deployment threat model. No privileged Docker mode or host Docker socket is permitted.

## Deferred
Durable workflow orchestration, model/tool gateways, approval service, secrets broker, trajectory/evidence persistence, event bus/outbox, full SDK/API and production deployment remain later milestones.