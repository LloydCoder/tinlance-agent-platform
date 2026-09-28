# ADR-011 — Durable database

**Status:** Accepted

PostgreSQL is the initial durable control-plane database. Relational state is preferred for agents, tasks, policies, approvals, credentials metadata, evidence metadata and audit records. Object storage is reserved for large artifacts.

**Decision:** do not introduce a graph database merely because entities have relationships.
