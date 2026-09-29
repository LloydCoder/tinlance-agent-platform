# Reference Agent Architecture

Reference agents are domain behavior above the Platform and SDK.

## Dependency rule

```
domain agent -> external SDK -> Platform API
```

Production agent code must not import:
- Platform kernel packages;
- Platform authorization/policy implementations;
- Platform secret or sandbox implementations;
- FAS/FDSE/TADS runtime internals.

Integration tests may import the reference Platform implementation solely to exercise the real HTTP contract locally. They do not mock or reimplement the Platform.

## Shared responsibilities

Reference agents own:
- goals;
- workflow composition;
- domain reasoning;
- domain tool selection;
- interpretation;
- domain outputs.

Platform owns:
- identity;
- tenancy;
- policy;
- approvals;
- tool authorization/execution;
- sandbox;
- secrets;
- evidence authority;
- audit/events;
- budgets.

SDK owns:
- transport;
- typed contract models;
- request/trace propagation;
- safe error classification;
- no authority decisions.

## Tool model

Tool descriptors are metadata contracts. A local descriptor cannot execute a tool or grant permission.

Each planned tool records:
- stable name;
- capability;
- action;
- resource;
- risk;
- approval requirement.

Actual consequential invocation uses the published R10 contract. The agent derives security-relevant execution fields from an immutable ToolPlan, requests approval with the exact execution intent when required, and sends the final invocation through SDK `tools.execute`. The Platform—not the agent—performs authorization, approval validation, timeout/budget/sandbox/secret enforcement, evidence and audit handling.


## R10 execution sequence

For a consequential plan:

1. The agent creates a Platform run.
2. The agent submits `tools.execute` through the external SDK.
3. Platform evaluates identity, tenant, capability, registration, policy, limits and required controls.
4. If approval is required, Platform returns a stable `execution_id` with `waiting_approval`; no tool side effect occurs.
5. The agent requests approval with the exact execution intent.
6. An authenticated approval authority decides through `approvals.decide`; requester self-approval is rejected by the Platform.
7. The agent resumes the exact intent with the same idempotency key and approved execution ID binding.
8. Platform re-authorizes and executes through the registered tool adapter, then commits evidence and audit events.
9. The agent may retrieve the authoritative terminal result with `executions.get`.

The reference agents never execute a tool locally and never treat approval state, model output, MCP metadata, or tool discovery as authority.
