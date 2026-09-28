# ADR-010 — Event architecture

**Status:** Accepted

Platform events require correlation IDs, idempotency and durable ordering where required. M0 will establish event contracts and a transactional outbox boundary.

**Decision:** PostgreSQL-backed outbox/events are the initial durable mechanism; a broker is introduced only when throughput or isolation measurements justify it.
