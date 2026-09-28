# M14 Status — Validation and Release Hardening

M14 closes the milestone sequence with conformance coverage across the platform surfaces, explicit fail-closed governance regression checks and release-readiness documentation.

## Release gates

- CI: lint, formatting, mypy, pytest and SQL/RLS checks green.
- Security: tenant isolation, fail-closed authorization, approvals, budgets and sandbox boundaries remain enforced.
- Evidence: trajectory hash-chain verification is available.
- Evaluation: safety-critical regression failures stop the evaluator.
- Operations: readiness is false if any required component is unhealthy.
- Isolation: production execution requires an explicit sandbox provider; unavailable isolation fails closed.

M14 does not claim that a reference in-memory provider is a production database, observability backend or sandbox. Those adapters remain explicit deployment responsibilities.
