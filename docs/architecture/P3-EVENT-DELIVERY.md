# P3 Event Delivery — Platform Runtime Contract

## Producer transaction

The application must begin a tenant-scoped database transaction, perform its domain state transition, append the event using the same transaction connection, and commit once. `PostgresEventStore` (when used) must never commit independently; a caller rollback must roll back both the state transition and event/outbox records.

## Publisher lifecycle

1. Claim an available outbox batch through `platform.claim_outbox_batch` using the current tenant-scoped database context.
2. Publish the immutable CloudEvents envelope to the configured transport.
3. Acknowledge only with the lease token returned for that outbox row.
4. On failure, call `platform.release_outbox` with a stable non-sensitive error code. The database applies bounded exponential backoff with jitter; once attempts reach `max_attempts`, the row is dead-lettered.
5. A stale, expired or mismatched lease cannot acknowledge or release a row.

A process crash after external publish but before acknowledgement can duplicate delivery. Consumers must deduplicate; the system promises at-least-once delivery, not exactly-once effects.

## Consumer transaction

Consumers must derive tenant identity from authenticated context, validate the event against the pinned TSIC schema, and apply the business effect and `platform.record_inbox_once` call in the same transaction. The inbox function returns true for a newly recorded receipt, false for a duplicate with the same digest, and raises if the same tenant/source/event/consumer identity arrives with a different digest. Acknowledgement follows only after that transaction commits.

## Security boundaries

- RLS is enforced on the inbox and existing event/outbox tenant tables.
- Event payloads are untrusted data, never authority grants.
- Trace/correlation metadata is for observability, not authorization.
- Error storage is limited to stable error codes; never persist raw exception text that may contain secrets.
- SQL functions are invoker-security functions and do not elevate privileges.

## Deployment evidence

A green migration test proves the schema/functions in CI only. Production readiness additionally requires an independently verified PostgreSQL deployment, transport adapter, worker supervision, metrics/alerts, backup/restore, incident procedures and a cross-system failure drill.
