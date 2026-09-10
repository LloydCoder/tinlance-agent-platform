# Dependency and Consumer Audit — M0

## Primary repositories

| Repository | Observed state | M0 classification |
|---|---|---|
| `LloydCoder/tinlance-agent-platform` | Private repository was empty at audit start | CORE — build here |
| `LloydCoder/tinlance-fdse` | Private repository was empty at audit time | CONSUMER — no platform code to migrate yet |
| `LloydCoder/tinlance-tads` | Private repository was empty at audit time | CONSUMER — no platform code to migrate yet |
| `LloydCoder/fde-mastery` | Mature public repository with an extensive `packages/platform-core` | REFERENCE / selective extraction |
| `LloydCoder/tinlance-threatfade` | Existing cybersecurity product | ISOLATE / adapter boundary |
| `LloydCoder/Tinlance` | Existing company/product repository | REFERENCE; not a platform dependency |

## FDE Mastery findings

The existing platform-core already contains substantial implementations and tests for identity/multitenancy, runtime, durable workflow ports, authorization, approvals, tool gateway, model gateway, events, evaluation, secrets, privacy, observability, persistence, MCP/A2A adapters and security. The repository also contains domain-specific FDE functionality that must not migrate into the generic platform.

Representative evidence includes:

- provider-neutral identity and tenant context;
- PostgreSQL/RLS-oriented tenancy decisions;
- bounded first-class runtime with checkpoints and cancellation;
- durable workflow boundary with leased tasks and replay semantics;
- capability-scoped tool gateway;
- provider-neutral model gateway;
- evaluation and security test suites;
- OpenTelemetry-oriented observability;
- security/red-team cases and SBOM tooling.

## Reuse classification

### ADOPT conceptually

- immutable `RequestContext` and provider-neutral `Principal`;
- tenant-first authorization ordering;
- runtime lifecycle and explicit budgets;
- port/adapter separation;
- idempotency as an execution invariant;
- durable workflow state separate from worker memory;
- model/tool gateway boundaries.

### ADAPTER

Existing FDE Mastery integrations and domain APIs should be wrapped through the future platform SDK rather than imported into the kernel.

### ISOLATE

FDE-specific engagement workflows, commercial entitlements, customer-value logic, domain adapters and training/curriculum code.

### REJECT as core dependency

Direct coupling to FDE Mastery package names, its historical domain layout, customer-specific logic, or any model/provider SDK used by an individual domain.

## Important architectural conclusion

Do **not** copy the entire FDE Mastery `platform-core` directory into this repository. It already mixes generic platform primitives with FDE-specific concerns. The new repository must be a clean-room platform boundary informed by those implementations, with selective reuse only after code-level review and licensing/ownership checks.
