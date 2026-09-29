# Changelog

## Unreleased — R10 Governed Execution Contract

- Added the authoritative `governed-execution.v1` execution boundary.
- Added exact identity/tenant/capability/tool-version binding and fail-closed policy handling.
- Completed approval decision/consumption semantics with requester self-approval rejection.
- Added execution fingerprinting and tenant-scoped consequential idempotency.
- Added execution status, evidence-to-execution binding, and correlated execution audit events.
- Added registered tool risk ceilings, tool-call budgets, timeout ceilings, sandbox/secret gates, and explicit ambiguous outcomes.
- Extended the SDK and Reference Agent Suite to use governed `tools.execute` rather than local consequential execution.
- Documented the distinction between reference in-memory providers and deployment-required durable providers.

All notable changes to Tinlance Agent Platform are recorded here.

## Unreleased

- Enterprise governed execution conformance and canonical M0-M14 verification.
- Complete authorization mediation at tool and MCP side-effect boundaries.
- Tenant/agent model-provider mediation and output-budget validation.
- Bounded context, evidence, trajectory and runtime budget controls.
- Expanded boundary threat models and executable conformance coverage.

## 1.0.0

- Established the governed agent-platform contract and enterprise baseline.
