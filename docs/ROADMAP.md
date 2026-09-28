# Agent Platform Roadmap

## Canonical enterprise sequence
M0 Foundation -> M1 Identity -> M2 Authorization -> M3 Approval -> M4 Runtime -> M5 Model Gateway -> M6 Tool/MCP Gateway -> M7 Sandbox -> M8 Orchestration -> M9 Memory -> M10 Evidence/Event -> M11 Observability -> M12 Evaluation -> M13 Domain SDK -> M14 Enterprise.

## Implementation mapping
M0 contracts/kernel/tenancy/boundaries. M1 identity/immutable agent versions. M2 deny-by-default authorization and policy. M3 same-run approval and exact binding. M4 runtime state, budgets and cancellation. M5 provider-neutral model gateway. M6 governed tools and MCP. M7 explicit isolated sandbox. M8 governed orchestration. M9 tenant-scoped memory and prompt-injection boundaries. M10 idempotent events/evidence/trajectory. M11 telemetry interfaces and adapters. M12 deterministic/adversarial evaluation. M13 stable SDK for domain repositories. M14 enterprise operations, SLOs, recovery, supply-chain provenance, tenant isolation and release conformance.

Every milestone requires implementation, tests, security validation and documentation; a green CI run alone is not a production claim.
