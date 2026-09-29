# Platform Contract Gap Register

## GAP-RA-001 — Approval decision and governed tool execution

**Status: CLOSED by R10 (2026-09-29)**

This gap existed when the reference-agent suite first landed: Platform API 1.1 exposed approval request creation but did not publish approval decisions or governed remote tool execution.

R10 now publishes and tests:

- `approvals.decide`
- `tools.execute`
- `executions.get`
- exact execution-intent fingerprints;
- authenticated, tenant-scoped approval decisions;
- requester self-approval rejection;
- single-use approval consumption;
- durable/conformance idempotency semantics;
- explicit pending, terminal and ambiguous execution outcomes;
- evidence/audit correlation.

The reference-agent suite has been migrated from the pre-R10 boundary to the authoritative R10 contract. All three agents now exercise the real SDK → Platform HTTP path for approval-gated execution.

### Residual deployment responsibilities

R10 is the authority contract, not a claim that every external deployment has production infrastructure. Operators must still supply the durable identity, approval, idempotency, budget, sandbox, secret, evidence and audit adapters described in `docs/R10-GOVERNED-EXECUTION.md`.

No reference-agent implementation may recreate those controls locally.
