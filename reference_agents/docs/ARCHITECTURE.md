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

Actual invocation is intentionally absent from API 1.1 and must be added to the Platform contract before any agent exposes it.
