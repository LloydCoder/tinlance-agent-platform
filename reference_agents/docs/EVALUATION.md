# Evaluation Methodology

The evaluation suite has four layers:

1. **Unit** — domain workflow and invariant tests.
2. **Contract** — public SDK operation allow-list tests.
3. **Integration** — real SDK over the real Platform HTTP reference implementation.
4. **Adversarial** — prompt injection, malicious content, prohibited actions, evidence-less findings, and replay-boundary checks.

The suite does not use an LLM as a test oracle. Assertions are deterministic.

## Release gate

A reference-agent change is releasable only when all four layers pass on Python 3.12, 3.13 and 3.14, plus the parent Platform CI and security workflows.

The current API 1.1 integration test intentionally stops at the last externally supported operation: approval request. This is a documented capability boundary, not a simulated success.
