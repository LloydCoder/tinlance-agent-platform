# P6 — Model and Tool Routing Mediation

**Status:** implementation candidate; not certified until exact-head CI, security workflows, cross-repository conformance, merge, and post-merge audit pass.

## Authority and scope

The Agent Platform is the only authority for route eligibility and consequential tool execution. A model route is metadata and a routing decision is evidence; neither grants a capability, approval, secret scope, sandbox access, or permission to execute a tool. OS and SDK callers cannot bypass Platform policy by supplying a preferred provider or model.

This phase hardens the provider-neutral model boundary with deterministic route selection based on registered route metadata, capability compatibility, tenant/agent allowlists, data classification, risk ceiling, cost estimate, provider availability, route enablement, and policy version. The existing ModelGateway remains the provider invocation boundary; ModelRouter selects a route but does not call providers or execute tools.

## Decision semantics

- Route registrations are immutable and route IDs are unique.
- Eligibility is conjunctive: every required condition must pass; no matching route means deny/no route.
- Candidate ordering is deterministic: ascending priority, then route ID.
- Provider availability is explicit request context; unavailable providers cannot be selected.
- Every allow or deny decision is passed to the configured evidence recorder before the caller receives it.
- If decision recording fails, routing fails closed and no decision is returned to the caller.
- Decision evidence includes a unique decision ID, selected route/provider/model where allowed, policy version, reason code, and trace ID.
- Caller-supplied preference, model output, retrieved content, registry metadata, and route descriptions do not override eligibility or grant authority.

## Security and reliability tests

The P6 test suite covers deterministic selection, tenant isolation, capability matching, data classification, risk ceiling, cost ceiling, disabled routes, provider availability, duplicate route registration, malformed context, no-eligible-route denial, and fail-closed audit recorder failure.

## Remaining exit gate

Before P6 certification, run and retain evidence for:
- Platform unit/type/lint/security/coverage workflows on the exact PR head.
- Cross-repository TSIC routing-authority conformance against the locked TSIC revision.
- Regression tests proving model routing does not bypass Platform authorization, approval, budget, secret, sandbox, or tool execution gates.
- Exact merged-SHA integration and post-merge workflows.
- A forensic audit reconciling the lock, manifest, phase matrix, route contracts, implementation, negative controls, and residual production limitations.

Repository conformance does not prove a live model provider, provider credential, production telemetry backend, or production deployment exists. Those remain unverified unless independently evidenced.
