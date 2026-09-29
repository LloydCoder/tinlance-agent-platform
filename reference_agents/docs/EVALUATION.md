# Evaluation Methodology

The evaluation suite has four layers:

1. **Unit** — domain workflow and invariant tests.
2. **Contract** — public SDK operation allow-list tests.
3. **Integration** — real SDK over the real Platform HTTP reference implementation.
4. **Adversarial** — prompt injection, malicious content, prohibited actions, evidence-less findings, and replay-boundary checks.

The suite does not use an LLM as a test oracle. Assertions are deterministic.

## Release gate

A reference-agent change is releasable only when all four layers pass on Python 3.12, 3.13 and 3.14, plus the parent Platform CI and security workflows.

The API 1.1 integration suite now exercises the real R10 approval-and-execution path for all three reference agents. It verifies a stable pending execution identity, exact approval binding, authenticated approval decision, same-intent idempotent resumption, terminal execution, evidence, audit events, and tenant-scoped execution status.


## R10 conformance cases

The executable suite covers:

- Security Research Agent: governed repository mutation.
- Software Engineering Agent: governed repository mutation.
- Intelligence Research Agent: governed external action.
- approval-required execution returns `waiting_approval` with an execution ID;
- approval requests carry the exact execution intent used by the final tool call;
- approval decisions are made by a distinct authenticated approver;
- the same idempotency key resumes an unresolved approval-gated execution;
- completed executions return evidence and audit references;
- `executions.get` returns the authoritative terminal state;
- no local executor, fabricated tool result, or simulated approval path exists.

The test harness uses deterministic reference adapters only to exercise the Platform's real authority boundary; the agents remain external-SDK consumers.
