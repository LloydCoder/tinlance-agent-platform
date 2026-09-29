# Platform Contract Gap Register

## GAP-RA-001 — Approval decision and governed tool execution are not public in API 1.1

**Status:** documented, non-blocking for the current reference-agent release.

The current Platform API 1.1 exposes `approvals.request` but not approval retrieval/decision and exposes no remote `tools.execute` operation.

The reference agents therefore:
- request approval through the SDK;
- observe the resulting event;
- never fabricate approval decisions;
- never execute a tool locally.

A future Platform API that publishes governed execution must first define:
- authenticated approval actor semantics;
- exact approval binding;
- action/resource/capability binding;
- expiry and replay behavior;
- pre-execution re-authorization;
- tool input/output contracts;
- evidence attribution;
- audit/security event semantics;
- idempotency;
- failure and timeout behavior.

Only after that contract exists should the external SDK and reference agents add those operations.
