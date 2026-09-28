# ADR-007 — Sandbox boundary

**Status:** Accepted

Isolation is selected by workload risk, data sensitivity and side-effect profile. Containers are a useful baseline but are not assumed to be sufficient for hostile workloads.

**Decision:** M7 will compare container, gVisor, Kata/microVM and remote-sandbox approaches against an explicit threat model before production selection.
