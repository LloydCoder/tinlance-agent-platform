# Enterprise Agent Platform Architecture

## Canonical sequence
M0 Foundation -> M1 Identity -> M2 Authorization -> M3 Approval -> M4 Runtime -> M5 Model Gateway -> M6 Tool/MCP Gateway -> M7 Sandbox -> M8 Orchestration -> M9 Memory -> M10 Evidence/Event -> M11 Observability -> M12 Evaluation -> M13 Domain SDK -> M14 Enterprise.

The repository's earlier implementation milestones grouped these controls differently. The canonical sequence above is now authoritative for architecture and security review.

## Planes
Control: identity, tenancy, authorization, policy, approvals, agents, budgets, governance.
Execution: runtime, orchestration, model providers, tools/MCP, sandbox, secrets.
Evidence: events/outbox, evidence, trajectory, observability, evaluation.

## Non-negotiable invariants
1. Model output is untrusted input.
2. No side effect bypasses authorization.
3. High-risk or irreversible actions require bound approval or are denied.
4. Delegated authority only attenuates and never changes tenant.
5. Credentials remain outside model context and resolve only at execution boundaries.
6. MCP tools and server content remain untrusted and policy mediated.
7. Sandbox failure never falls back to unrestricted subprocess execution.
8. Events are tenant-scoped and idempotent; trajectory is tamper-evident.
9. Domain products consume the SDK and never become platform dependencies.

These boundaries align with current guidance on agent identity, approvals, sandbox/harness separation and MCP authorization. See the cited research in the project audit report.
