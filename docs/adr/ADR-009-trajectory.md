# ADR-009 — Trajectory architecture

**Status:** Accepted

A trajectory records attributable execution transitions without indiscriminately retaining sensitive model content. References, hashes, policy decisions, tool calls, approvals, retries and outputs are represented explicitly.

**Decision:** sensitive payload capture is opt-in, redacted and governed by data-classification/retention policy.
