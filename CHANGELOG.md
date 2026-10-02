# Changelog

## 2026-10-02 — Enterprise Evolution M15-M19

- M15: added production durability primitives for transactional outbox publication and distributed worker lease semantics.
- M16: added provider-neutral federated identity validation and execution-scoped secret handles.
- M17: added secure remote-agent discovery metadata and authority-attenuating delegation contracts.
- M18: added correlation context, SLO measurement and safety-aware evaluation release gates.
- M19: added evidence-backed enterprise production acceptance and GA certification contract.
- Reconciled enterprise documentation to distinguish repository controls from external production infrastructure.

## 2026-09-29 — R10 Governed Execution Contract

- Added the authoritative governed-execution.v1 boundary.
- Added exact identity/tenant/capability/tool-version binding and fail-closed policy handling.
- Completed approval decision/consumption semantics with requester self-approval rejection.
- Added execution fingerprinting and tenant-scoped consequential idempotency.
- Added execution status, evidence-to-execution binding, and correlated execution audit events.
- Added registered tool risk ceilings, tool-call budgets, timeout ceilings, sandbox/secret gates, and explicit ambiguous outcomes.
- Extended the SDK and Reference Agent Suite to use governed tools.execute rather than local consequential execution.
- Documented the distinction between reference in-memory providers and deployment-required durable providers.

## 1.0.0

- Established the governed agent-platform contract and enterprise baseline.
