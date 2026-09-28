# M1 Status — Core Domain

M1 establishes the first executable governed-agent core.

## Delivered
- versioned M1 contracts for agents, tasks, runs, approvals, budgets, tools, sandbox requests and evidence links
- immutable tenant-scoped agent registry
- deterministic run lifecycle state machine
- fail-closed human approval lifecycle
- hard monotonic turn/tool/time budgets
- tool gateway requiring tenant and capability authorization before execution
- sandbox policy boundary with explicit no-unrestricted-fallback behavior
- public SDK integration surface without package-internal imports
- PostgreSQL persistence and tenant RLS for runs, approvals and budgets
- unit, architecture and SQL isolation tests

## Security posture

The sandbox package is a policy/contract boundary, not an OS-level isolation claim. Production execution must bind this contract to an actual isolated provider (container/VM/equivalent). If that provider is unavailable, execution fails closed. This separation follows the current industry pattern of keeping the trusted harness/control plane separate from compute. citeturn0search2turn0search8

## Why these boundaries

Current agent runtimes separate agent definitions, execution loops, approvals, tools, sandbox compute and observability rather than treating model output as authority. citeturn1search0turn1search7turn1search9

## Explicitly deferred

Provider adapters, durable external workflow engine, production API/worker, model gateway, MCP transport, secrets broker, persistent event/outbox implementation, trajectory store, observability backend and production sandbox implementation are M2+.

M1 is therefore **core-domain complete**, not a claim of production readiness.
