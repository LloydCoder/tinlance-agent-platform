# M4 Runtime Threat Model

## Abuse cases

- Run transitions from terminal state back to active state.
- Turn or token budgets are bypassed through retries or duplicate calls.
- A failed model/tool call leaves side effects without a terminal record.
- Cancellation or timeout is treated as success.
- Duplicate execution creates repeated consequential side effects.

## Controls

Runtime state transitions are explicit and terminal-state constrained. Hard turn/cost budgets are checked before consequential work. Failures are represented as failed terminal states. Idempotency/durability contracts must bind retries to the same run/action identity.

## Test obligations

Exercise terminal-state rejection, budget exhaustion, failure propagation, duplicate invocation and cancellation/timeout semantics at the orchestration boundary.
