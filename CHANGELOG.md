# Changelog

## 1.1.0 — 2026-09-28

- Hardened evidence and trajectory stores with thread-safe append/verification semantics.
- Hardened event storage against mutable payloads, duplicate IDs and secret-bearing fields.
- Added tenant/agent allowlists and response-budget validation to the model gateway.
- Added complete mediation and approval binding to the MCP gateway.
- Added a governed end-to-end execution service spanning identity context, authorization, model gateway, tool gateway, evidence, events, trajectory and security observability.
- Added conformance coverage for the end-to-end governed path and cross-tenant fail-closed behavior.
- Reconciled the canonical M0–M14 enterprise sequence with executable implementation evidence.

## 1.0.0 — 2026-09-28

- Established the canonical M0–M14 governed agent platform contract.
- Added enterprise conformance, dependency auditing, SBOM generation and expanded threat models.
