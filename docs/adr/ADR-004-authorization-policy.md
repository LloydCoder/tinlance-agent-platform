# ADR-004 — Authorization and policy

**Status:** Accepted

Capability, permission, credential and authorization remain separate concepts. Policy decisions are deterministic, inspectable, versioned and enforced outside model reasoning. Default behavior is deny.

**Decision:** M2 will evaluate a dedicated policy engine against a provider-neutral policy port; no LLM is a policy decision point.
