# M3 Status — Durability

M3 defines durable-run primitives: tenant-scoped idempotency, append-only event sequencing, transactional-outbox tables and bounded exponential retry policy.

The SQL migration is the persistence contract; application repositories remain behind ports so the core stays framework-neutral. A publisher must claim pending outbox rows transactionally and mark them published only after successful delivery.
