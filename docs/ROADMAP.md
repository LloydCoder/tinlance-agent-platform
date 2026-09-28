# Agent Platform Roadmap

M0 Foundation — bounded contracts, kernel, identity, tenancy, authorization, policy.
M1 Core Domain — agents, runs, approvals, budgets, governed tools, sandbox boundary.
M2 Execution — model/tool provider ports, runner, secret broker boundary, events/evidence reference stores.
M3 Durability — PostgreSQL repositories, transactional outbox, idempotency, retries, resumable runs.
M4 Governance — policy composition, capability grants, approval binding, emergency stop, step-up controls.
M5 Context — context assembly, memory ports, classification/redaction, prompt-injection boundaries.
M6 MCP — MCP transport, server/tool registration, per-tool auth, scope step-up and capability mapping.
M7 Evidence — append-only trajectory, provenance, tamper evidence, audit records and retention contracts.
M8 Observability — OpenTelemetry traces/metrics/logs, cost accounting, security events and health.
M9 Evaluation — deterministic eval runner, adversarial suites, regression corpus and safety gates.
M10 Isolation — production sandbox adapter, resource/network/filesystem controls and kill semantics.
M11 API/SDK — service API, worker, scheduler, CLI and stable external SDK surface.
M12 Multi-agent — delegation, handoffs, child-agent authority narrowing, concurrency and cancellation.
M13 Operations — deployment, migrations, configuration, supply-chain controls, backup/recovery and SLOs.
M14 Validation — end-to-end conformance, threat-model closure, release hardening and v1.0 readiness.

Each milestone must ship implementation, tests, security validation and documentation; later milestones may not silently backfill earlier security invariants.
