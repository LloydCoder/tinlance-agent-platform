# Agent Platform ↔ Agent OS Forensic Integration Audit

Date: 2026-09-29
Contract baseline: Agent Platform API v1.1
Repositories: tinlance-agent-platform and tinlance-agent-os

## Executive result

The repository-level integration is now coherent and contractually bounded. Agent Platform is the authoritative governed execution substrate; Agent OS owns sessions, tasks, workflows, workspaces, applications and user-facing orchestration. No open pull requests remain in either repository.

The integration was audited from code, tests, workflows, API boundaries, lifecycle state, security controls and documentation. Identified integration blockers were implemented and regression-tested.

## Ownership matrix

| Area | Authoritative owner | Integration rule |
|---|---|---|
| Principal/tenant authority | Agent Platform | OS propagates context; Platform binds it to authenticated identity |
| Authentication | Agent Platform boundary | OS supplies credential; production resolver validates it |
| Authorization/policy | Agent Platform | OS cannot grant consequential authority |
| Approval authority | Agent Platform | OS displays/coordinates opaque approval references |
| Governed execution | Agent Platform | OS requests and reconciles Platform runs |
| Sessions/tasks/workflows | Agent OS | Platform run is a governed execution instance, not an OS task replacement |
| Tools/MCP/sandbox | Agent Platform | OS cannot bypass gateway/security boundary |
| Evidence/audit/events | Agent Platform | OS consumes opaque references and correlates locally |
| Workspace/application UX | Agent OS | Platform remains independent of OS |

## Blockers fixed

### 1. Authenticated identity binding
The HTTP boundary now resolves the bearer credential before dispatch and requires body tenant/subject assertions to match the authenticated principal. The request passed to the handler is rebuilt from the authenticated principal rather than trusting caller-supplied identity.

### 2. API-version ambiguity
Agent OS and the Platform boundary now require API v1.1 explicitly. Incompatible versions receive HTTP 426.

### 3. Trace-context ambiguity
Optional traceparent is validated against W3C Trace Context syntax and rejects all-zero identifiers. The validation was corrected to inspect the exact 32-hex trace ID and 16-hex span ID fields rather than adjacent delimiter positions.

### 3a. Request-ID boundary ambiguity
Request IDs are now required to be non-blank, printable, normalized and bounded to 256 characters; this prevents whitespace-only or oversized identifiers from entering the idempotency boundary.

### 4. Consequential-request replay
Guarded side-effect operations now have bounded request-idempotency. Identical deliveries replay the original response; reusing a request ID for a different consequential request returns HTTP 409. Concurrent deliveries are serialized at the reference boundary so duplicate side effects cannot race through.

### 5. Idempotency header drift
If Idempotency-Key is supplied, the HTTP boundary requires it to match X-Request-ID.

### 6. OS task spoofing
Agent OS dispatch now requires a durable local task and verifies the request against persisted task identity. An arbitrary task payload can no longer manufacture an OS task at dispatch time.

### 7. OS consequential-request replay
Agent OS now derives deterministic request IDs from canonical operation/payload data for run creation, cancellation and approval requests. These operations are explicitly retryable because the same logical request reuses the same replay key across transport retries and process restarts.

### 8. OS lifecycle drift
Agent OS now reconciles durable task state when a Platform run is cancelled or an approval is requested. Session/task/workflow ownership remains in OS while governed execution remains in Platform.

### 9. Test-fixture import failure
Repository-local test package resolution was made explicit so CI does not accidentally import an unrelated installed tests package.

### 10. Documentation drift
Historical M0 architecture wording was separated from the current M2-M11 implementation boundary. Canonical Platform↔OS integration contracts were added to both repositories.

## Canonical artifacts

- Agent Platform: docs/architecture/agent-platform-agent-os-integration.md
- Agent OS: docs/architecture/agent-platform-integration.md
- Platform architecture: docs/ARCHITECTURE.md
- OS architecture: docs/ARCHITECTURE.md
- OS threat model: security/threat-model.md
- OS security controls: docs/SECURITY-CONTROLS.md

## Verification

Platform final CI: success.
Platform quality matrices: Python 3.12, 3.13 and 3.14 passed; SQL job passed.
Agent OS final CI: success.
Agent OS final matrix: Python 3.12, 3.13 and 3.14 passed; architecture boundary passed.
Agent OS final lifecycle regression suite passed in all matrix jobs.
Latest hardening changes additionally add regression coverage for deterministic consequential replay keys and exact W3C trace-context field validation.
Both repositories currently have zero open pull requests.

## Security model verified

The integration boundary explicitly treats model output, retrieved content, tool output, memory, extension data and peer-agent messages as untrusted. Authority comes from authenticated principals, Platform authorization/policy and Platform-owned approvals—not from model output or OS state.

Repository tests cover authenticated tenant binding, malformed boundary inputs, API-version mismatch, exact trace-context validation, request-ID constraints, request replay/conflict, deterministic OS consequential replay keys, OS task persistence, Platform run cancellation reconciliation and approval-state reconciliation.

## Adversarial conclusions

An OS caller cannot widen tenant or subject authority merely by changing request-body fields. An OS caller cannot dispatch an unpersisted task through the local service boundary. A duplicate consequential request with the same request ID cannot create a second Platform result at the reference API boundary. A stale or mismatched idempotency key is rejected. Platform evidence remains an opaque authority owned by Platform.

## Explicit production deployment seams

The repository HTTP server is a reference contract boundary, not a complete Internet-facing gateway. Production deployment still requires a standards-based credential verifier, hardened TLS or secure RPC, durable idempotency storage, durable execution/recovery infrastructure, production policy/authorization services, isolated execution infrastructure, secret management, telemetry/audit retention and operational controls.

These are explicitly documented deployment responsibilities rather than hidden integration gaps.

## External security alignment

The design was checked against current NIST agent identity/authorization work, OWASP 2026 agent-security guidance, and the Model Context Protocol 2026-07-28 direction. The MCP 2026-07-28 release emphasizes stateless request handling, explicit request metadata, routable method/name headers and authorization hardening; the Tinlance boundary follows the same principle of explicit per-request identity rather than hidden transport authority.

## Acceptance result

Repository-level Agent Platform ↔ Agent OS integration acceptance criteria are satisfied: ownership is explicit, authority flow is explicit, cross-layer contracts are documented, lifecycle reconciliation is tested, security-sensitive boundaries are enforced, documentation is reconciled, open PRs are closed, and final CI is green.