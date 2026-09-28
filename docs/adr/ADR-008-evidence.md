# ADR-008 — Evidence architecture

**Status:** Accepted

Evidence is distinct from telemetry, trajectory and audit. Meaningful actions can emit structured evidence with source, provenance, timestamp, content hash and classification.

**Decision:** evidence storage will support tamper-evident integrity without claiming immutability until the underlying storage and verification mechanisms are implemented and tested.
