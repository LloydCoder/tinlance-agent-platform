# ADR-006 — Tool gateway

**Status:** Accepted

Every platform-managed tool call crosses a registered, versioned, capability-scoped gateway. The gateway validates identity, tenant, schema, policy, risk, approval and idempotency before execution.

**Decision:** MCP, HTTP, RPC, SaaS and local tools are adapters behind this boundary.
