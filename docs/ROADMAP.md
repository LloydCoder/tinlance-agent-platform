# Canonical Agent Platform Roadmap

This is the canonical milestone sequence for Tinlance Agent Platform and supersedes earlier implementation-order labels in historical status documents.

M0 -> M1 Identity -> M2 Authorization -> M3 Approval -> M4 Runtime + M5 Model Gateway -> M6 Tool/MCP Gateway -> M7 Sandbox -> M8 Orchestration -> M9 Memory -> M10 Evidence/Event -> M11 Observability -> M12 Evaluation -> M13 Domain SDK -> M14 Enterprise

## Scope

M0 Foundation: contracts, kernel, package boundaries, RLS and threat model.

M1 Identity: normalized principals, agent identity/versioning and tenant binding.

M2 Authorization: explicit capabilities, deny-by-default checks and complete mediation.

M3 Approval: resumable human-review state, exact action binding and expiry.

M4 Runtime: fail-closed lifecycle, hard budgets and terminal-state integrity.

M5 Model Gateway: provider-neutral model port, usage validation and tenant/agent attribution.

M6 Tool/MCP Gateway: tool registration, capability/resource scoping and transport isolation.

M7 Sandbox: isolated workspace, command/path/network policy and fail-closed provider selection.

M8 Orchestration: agent runner, handoff/delegation boundary and resumable execution contracts.

M9 Memory: tenant-scoped memory/context, trust labels, classification and secret redaction.

M10 Evidence/Event: append-only events, evidence, trajectory hashes and audit records.

M11 Observability: correlated traces, metrics and security events; no secret content by default.

M12 Evaluation: deterministic regression corpus and safety-critical release gates.

M13 Domain SDK: stable public consumer surface and declarative domain registration.

M14 Enterprise: RLS integrity, production configuration, backup/recovery contracts, supply-chain controls, threat-model closure and release gates.

Every milestone must ship implementation, tests, security validation and documentation. Historical status files are retained for traceability; this roadmap and current repository state are authoritative.

## Non-goals

The platform does not become FDSE, TADS, ThreatFade, Hezqara, ReconOS, FusionOps or Agentic OS. The platform does not grant authority based on model confidence, external intelligence, prompt content or tool registration alone.
