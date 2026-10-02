# M18 — Reliability, Observability & Continuous Evaluation

M18 turns existing telemetry and deterministic evaluation primitives into explicit operational contracts.

Controls added in this phase:

- immutable correlation context carrying tenant, run, execution and trace identity;
- explicit SLO targets and measurable good/total event ratios;
- release evaluation gates with configurable pass-rate thresholds;
- mandatory safety-critical regression blocking;
- no evaluation result can grant runtime authority.

Production telemetry should map these identifiers to OpenTelemetry semantics. Continuous evaluation should include adversarial, failure-path, cost and reliability cases rather than only happy-path correctness.
