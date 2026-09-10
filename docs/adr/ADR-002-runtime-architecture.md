# ADR-002 — Runtime architecture

**Status:** Accepted

Use a framework-neutral runtime port with explicit task/run lifecycle, cancellation, budgets, checkpoints and failure states. Workers are disposable; durable state is external to process memory.

**Decision:** begin as a modular monolith and add distributed workers only when operational evidence requires them.
