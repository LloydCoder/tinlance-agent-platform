# Tinlance Agent Platform SDK v0.1 Contract

**Status:** Forensic baseline extracted from the current repository  
**Date:** 2026-09-29  
**Platform baseline:** Agent Platform API v1.1  
**Repository:** `LloydCoder/tinlance-agent-platform`  
**Purpose:** Source-of-truth input for the external `tinlance-agent-platform-sdk` v0.1 design

## 1. Contract authority

This document records the **currently implemented and executable** Platform API contract as observed on `main` at commit `caaeb7a9b3689d665a61e0b2b014282f939d134c`.

The contract was derived from:

- `packages/api/src/tinlance_agent_platform_api/http.py`
- `packages/api/src/tinlance_agent_platform_api/service.py`
- `tests/support/reference_gateway.py`
- `tests/api/test_agent_os_gateway.py`
- `packages/contracts/src/tinlance_agent_platform_contracts/models.py`
- `packages/contracts/src/tinlance_agent_platform_contracts/lifecycle.py`
- agent, approval, event, evidence and tool reference implementations
- `docs/ARCHITECTURE.md`
- `docs/ROADMAP.md`
- `docs/architecture/agent-platform-agent-os-integration.md`
- `docs/audits/agent-platform-agent-os-integration-2026-09-29.md`

**Important:** current implementation and executable tests define what is actually available. Architectural aspirations that are not exposed by the HTTP boundary are not treated as SDK v0.1 API surface.

## 2. Critical finding: the repository already contains an internal SDK package

The Platform repository currently contains `packages/sdk`, but it is **not an HTTP/client SDK**.

Its public surface exports internal/domain composition primitives such as:

- `AgentRegistry`
- `ApprovalService`
- `BudgetService`
- `ContextService`
- `GovernanceService`
- `MCPToolGateway`
- `ModelGateway`
- `RunStateMachine`
- `SandboxPolicy`
- `ToolGateway`
- `DomainRegistration`

It imports Platform implementation packages directly.

Therefore:

> `packages/sdk` is the current internal/domain SDK surface described by M13; it must not be mistaken for the planned external network client SDK.

The planned `tinlance-agent-platform-sdk` should be a separate consumer-facing package/repository whose transport crosses the Platform API boundary and whose public contract does not expose Platform internals.

## 3. Wire endpoint inventory

### Implemented endpoint

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/agent-platform` | Single versioned operation gateway |

There are currently **no separately exposed REST endpoints** for runs, approvals, tools, evidence, events, agents, or capabilities in the reference HTTP boundary.

The HTTP server rejects other paths with **404**.

The API is therefore currently an **operation-envelope API**, not a conventional resource-oriented REST API.

### Transport

Request:

- `Content-Type: application/json`
- `Authorization: Bearer <credential>`
- `X-Tinlance-API-Version: 1.1`
- `X-Request-ID: <normalized request id>`
- optional `Idempotency-Key`
- optional W3C `traceparent`

Response:

- `Content-Type: application/json`
- `Cache-Control: no-store`
- `X-Content-Type-Options: nosniff`
- `X-Tinlance-API-Version: 1.1`

The reference server is HTTP-only and intentionally not a production Internet gateway. Production deployment must provide hardened TLS/secure RPC and a standards-based credential verifier.

## 4. Request envelope

Every successful operation request has this logical shape:

```json
{
  "tenant_id": "tenant-a",
  "subject_id": "user-a",
  "operation": "health",
  "payload": {}
}
```

### Fields

| Field | Type | Required | Constraints |
|---|---|---:|---|
| `tenant_id` | string | yes | Must equal authenticated principal tenant; normalized/non-empty |
| `subject_id` | string | yes | Must equal authenticated principal subject; normalized/non-empty |
| `operation` | string | yes | Non-empty, normalized |
| `payload` | object | yes/effectively | Defaults to `{}`; must be an object |

The caller cannot use `tenant_id` or `subject_id` as an authority source. The HTTP boundary resolves the bearer credential first, verifies those assertions against the authenticated principal, and rebuilds the dispatched request from the authenticated principal.

## 5. Response envelope

Successful responses use:

```json
{
  "status": "ok",
  "payload": {}
}
```

The reference implementation currently uses:

- `status: "ok"` for reads/health
- `status: "accepted"` for consequential operations

The HTTP status is currently **200** for successful operations, including `accepted` responses.

Error responses use a minimal shape:

```json
{
  "error": "error_code"
}
```

No stable machine-readable error detail field is currently exposed.

## 6. Authentication

### Current wire contract

Authentication is:

```
Authorization: Bearer <credential>
```

The HTTP layer only parses the bearer credential and passes the resulting token to an injected `PrincipalResolver`.

The reference test resolver is an in-memory token-to-principal mapping.

### Production boundary

The repository explicitly requires production deployments to replace this resolver with a standards-based verifier handling the deployment's issuer, audience, signature, expiry, credential lifecycle and scope requirements.

Therefore SDK v0.1 should support **opaque bearer credentials** and must not assume a particular JWT/OIDC implementation.

The SDK must never infer tenant or subject authority from locally supplied configuration when the server is authoritative.

## 7. Principal model

The canonical principal contract is:

```text
Principal
  subject_id: str
  principal_type: str
  tenant_id: str
  roles: frozenset[str]
  scopes: frozenset[str]
```

The request context additionally carries:

```text
RequestContext
  request_id: str
  tenant_id: str
  principal: Principal
  environment: str
  trace_id: str | None
```

The HTTP envelope exposes only:

- authenticated tenant
- authenticated subject

Principal type, roles and scopes are server-side authority context; they are not caller-controlled request authority.

### SDK rule

The SDK may represent principal-related response data where an operation exposes it, but it must never allow a caller to manufacture an authoritative principal by setting `tenant_id`, `subject_id`, roles or scopes locally.

## 8. API versioning

Current API version:

```
1.1
```

Required request header:

```
X-Tinlance-API-Version: 1.1
```

A missing or incompatible version receives:

```
HTTP 426 Upgrade Required
{"error":"api_version_required"}
```

The response also advertises:

```
X-Tinlance-API-Version: 1.1
```

### SDK rule

SDK v0.1 must send API version **1.1 explicitly** and expose the negotiated/expected API version as a typed constant or configuration value.

SDK version and Platform API version are independent:

```
SDK version != API version
```

## 9. Request IDs and trace context

### Request ID

`X-Request-ID` is required.

Current constraints:

- non-empty
- trimmed/normalized
- maximum 256 characters
- printable ASCII only

Invalid request IDs receive **400**.

### Idempotency-Key

Optional on the wire, but if present:

```
Idempotency-Key == X-Request-ID
```

Mismatch receives **400**.

The Platform's consequential-request contract therefore uses the request ID as the replay identity.

### Traceparent

Optional W3C Trace Context `traceparent`.

Current validation requires:

- exact W3C syntax
- 32-hex trace ID
- 16-hex span ID
- neither identifier may be all zero

Invalid trace context receives **400**.

### SDK rule

The SDK should generate a request ID for every operation unless the caller explicitly supplies one, propagate it consistently, and make the idempotency behavior explicit.

It should not silently generate a different idempotency key from the request ID for consequential operations.

## 10. Idempotency

The current reference API treats these operations as consequential/idempotency-guarded:

- `runs.create`
- `runs.cancel`
- `approvals.request`

The Platform computes a canonical fingerprint from:

- tenant
- subject
- operation
- payload

If a request ID has already been used:

### Same fingerprint

The previously stored response is replayed.

### Different fingerprint

The Platform returns:

```
HTTP 409 Conflict
{"error":"idempotency_conflict"}
```

### Concurrent duplicate

The reference boundary serializes guarded requests under a lock so duplicate deliveries cannot both execute through the reference side-effect boundary.

### Current limitation

The reference implementation stores idempotency state in memory and bounds it to **1024 entries**.

It is not durable across process restarts and is not a distributed exactly-once mechanism.

Production requires durable idempotency/recovery infrastructure.

### SDK rule

SDK v0.1 must:

- support caller-supplied request IDs;
- automatically provide safe request IDs when absent;
- treat guarded operations as retry-sensitive;
- never automatically retry a consequential operation with a new request ID;
- surface HTTP 409 as a typed idempotency conflict.

## 11. Implemented operation inventory

The current reference gateway exposes these operations:

| Operation | Input payload | Output payload | HTTP | Consequential |
|---|---|---|---:|---:|
| `health` | `{}` | `ready: bool` | 200 | no |
| `principal.get` | `{}` | `user_id: string` | 200 | no |
| `agents.list` | `{}` | `agents[]` | 200 | no |
| `capabilities.list` | `agent_id` | `capabilities[]` | 200 | no |
| `runs.create` | `task_id, agent_id, intent` | `run_id, task_id, state, agent_id` | 200 | yes |
| `runs.cancel` | `run_id` | `run_id, task_id, state` | 200 | yes |
| `approvals.request` | `run_id, action, resource, reason` | `approval_id` | 200 | yes |
| `runs.events` | `run_id` | `events[]` | 200 | no |
| `runs.evidence` | `run_id` | `evidence[]` | 200 | no |

The operation names above are the **current reference API surface**, not a claim that all future Platform capabilities must retain these names.

## 12. Operation schemas

### 12.1 health

Request:

```json
{
  "operation": "health",
  "payload": {}
}
```

Response:

```json
{
  "status": "ok",
  "payload": {
    "ready": true
  }
}
```

### 12.2 principal.get

Request payload:

```{}
```

Response payload:

```json
{
  "user_id": "user-a"
}
```

The current implementation exposes the authenticated subject identifier only.

### 12.3 agents.list

Request payload:

```{}
```

Response:

```json
{
  "agents": [
    {
      "agent_id": "UUID",
      "name": "security-agent",
      "version": "1.0.0"
    }
  ]
}
```

Agents are tenant-scoped.

Agent versions are immutable in the underlying registry.

### 12.4 capabilities.list

Request:

```json
{
  "agent_id": "UUID"
}
```

Response:

```json
{
  "capabilities": [
    {
      "capability_id": "repository.read"
    }
  ]
}
```

This is discovery. Capability possession does not itself authorize a side effect.

### 12.5 runs.create

Required payload:

```json
{
  "task_id": "UUID",
  "agent_id": "UUID",
  "intent": "inspect repository"
}
```

Validation includes:

- task ID must parse as UUID;
- agent ID must parse as UUID;
- agent must exist in the authenticated tenant;
- the registered agent owner must equal the authenticated subject;
- intent must be non-empty.

Response:

```json
{
  "run_id": "UUID",
  "task_id": "UUID",
  "state": "running",
  "agent_id": "UUID"
}
```

Current reference behavior transitions the newly created run from `created` to `running` before returning.

### 12.6 runs.cancel

Request:

```json
{
  "run_id": "UUID"
}
```

Response:

```json
{
  "run_id": "UUID",
  "task_id": "UUID",
  "state": "cancelled"
}
```

The run must belong to the authenticated tenant.

### 12.7 approvals.request

Request:

```json
{
  "run_id": "UUID",
  "action": "security.scan",
  "resource": "repo:example",
  "reason": "scan requires governed approval"
}
```

Response:

```json
{
  "approval_id": "UUID"
}
```

Current reference behavior:

1. validates run ownership;
2. creates a pending approval;
3. gives the approval a 10-minute expiry in the reference gateway;
4. transitions the run to `waiting_approval`;
5. emits `approval.requested`.

### 12.8 runs.events

Request:

```json
{
  "run_id": "UUID"
}
```

Response:

```json
{
  "events": [
    {
      "event_id": "UUID",
      "event_type": "run.created",
      "occurred_at": "RFC3339 timestamp",
      "request_id": "request-id",
      "correlation_id": "request-id",
      "workspace_id": "tenant-a",
      "task_id": null,
      "agent_id": null,
      "platform_run_id": "UUID",
      "payload": {}
    }
  ]
}
```

The reference HTTP adapter currently derives some correlation/envelope fields at read time. SDK v0.1 should treat the response schema as an opaque event contract and must not infer that all fields are authoritative event-store fields.

### 12.9 runs.evidence

Request:

```json
{
  "run_id": "UUID"
}
```

Response:

```json
{
  "evidence": [
    {
      "evidence_id": "UUID"
    }
  ]
}
```

The current HTTP operation intentionally exposes **evidence references only**, not evidence content or the full internal `Evidence` object.

## 13. Run lifecycle

Canonical run statuses:

```
created
running
waiting_approval
succeeded
failed
cancelled
```

The state machine is fail-closed and rejects invalid transitions.

The current HTTP gateway explicitly exercises:

```
created -> running
running -> waiting_approval
running -> cancelled
```

The underlying Platform runtime also defines successful and failed terminal states.

### SDK rule

SDK models should represent the complete canonical enum, while operation-specific behavior must follow the server's actual transition contract.

SDK v0.1 must not invent client-side transitions.

## 14. Approval lifecycle

Canonical statuses:

```
pending
approved
rejected
expired
```

Current reference behavior:

```
request -> pending
pending -> approved
pending -> rejected
pending -> expired
```

An approval is bound to:

- tenant
- run
- action
- resource
- requester
- expiry

The underlying approval verifier also requires exact binding to tenant, run, action and resource before a consequential tool execution can proceed.

### Critical API gap

The current HTTP boundary exposes **approval creation only**:

```
approvals.request
```

It does **not** expose HTTP operations for:

- retrieving an approval;
- approving an approval;
- rejecting an approval;
- explicitly cancelling an approval.

Those are internal/reference service capabilities today.

Therefore SDK v0.1 must **not** expose fake remote approval-decision methods until a versioned API contract exists.

## 15. Tool boundary

The Platform has an internal governed `ToolGateway`.

Its authority chain is:

```
RequestContext
 -> capability request
 -> tenant binding
 -> complete mediation
 -> policy decision
 -> approval when required
 -> registered tool
 -> executor
```

Tool calls are bound to:

- tenant
- run
- tool name
- capability
- action
- resource

The gateway rejects tenant mismatch, capability mismatch, action mismatch, resource mismatch and missing exact approval.

### Critical API gap

There is currently **no HTTP operation for direct tool execution or tool registration** in the reference gateway.

Therefore:

- SDK v0.1 must not invent `tools.execute`;
- SDK v0.1 must not bypass the Platform tool gateway;
- future remote tool APIs must preserve the complete-mediation boundary.

This is deliberate and safer than exposing an uncontracted tool endpoint.

## 16. Evidence

The internal evidence model is:

```text
Evidence
  evidence_id: UUID
  tenant_id: str
  run_id: UUID
  content_hash: str
  content: str
  sequence: int
```

Reference constraints include:

- tenant normalization;
- non-empty content;
- maximum content size of 1,000,000 characters;
- SHA-256 content hashing;
- per-run sequence numbers;
- verification of sequence/hash integrity.

### External API

The current HTTP operation exposes only:

```
runs.evidence -> evidence_id[]
```

It does not expose content, hashes, provenance or verification methods through this boundary.

Therefore SDK v0.1 should model evidence references rather than pretending the internal evidence object is a public API resource.

## 17. Events

The internal event model is:

```text
Event
  event_id: UUID
  tenant_id: str
  run_id: UUID
  event_type: str
  payload: Mapping[str, str]
  occurred_at: datetime
```

Reference store guarantees include:

- tenant-scoped reads;
- immutable event IDs;
- bounded payload field count;
- rejection of sensitive-looking payload keys/values;
- timezone-aware timestamps.

Current externally exposed operation:

```
runs.events
```

This is a read/list operation scoped to one run.

### Current limitation

There is no HTTP event-stream endpoint or cursor protocol.

Therefore SDK v0.1 should implement list/read semantics only and defer streaming until the Platform publishes a stable streaming contract.

## 18. Pagination

### Finding: no pagination contract currently exists

The current API operations return complete bounded lists:

- `agents.list`
- `capabilities.list`
- `runs.events`
- `runs.evidence`

No request or response fields currently define:

- cursor;
- next cursor;
- page size;
- offset;
- total count;
- continuation token.

Therefore pagination is **not part of SDK v0.1**.

The SDK must not fabricate a pagination abstraction over unpaginated server behavior.

A future pagination contract should be introduced at the Platform API level first.

## 19. Error contract

Current HTTP mappings:

| Condition | HTTP | Body |
|---|---:|---|
| unknown path | 404 | `{"error":"not_found"}` |
| missing/invalid bearer | 401 | `{"error":"unauthorized"}` |
| tenant/subject mismatch | 403 | `{"error":"forbidden"}` |
| unsupported API version | 426 | `{"error":"api_version_required"}` |
| idempotency conflict | 409 | `{"error":"idempotency_conflict"}` |
| invalid request / malformed JSON / invalid trace context / invalid IDs | 400 | `{"error":"invalid_request"}` |
| non-JSON content type | 415 | `{"error":"json_required"}` |
| request body above 1 MiB | 413 | `{"error":"request_too_large"}` |
| unexpected server failure | 500 | `{"error":"platform_error"}` |

The reference HTTP boundary does not expose exception class names, stack traces or sensitive diagnostic details.

### SDK error mapping

SDK v0.1 should provide typed errors corresponding to the stable HTTP contract, including at least:

- AuthenticationError
- PermissionError
- ApiVersionError
- IdempotencyConflictError
- InvalidRequestError
- UnsupportedMediaTypeError
- RequestTooLargeError
- PlatformError

The SDK should preserve HTTP status and stable error code where possible.

It must not expose raw authorization tokens in error strings or logs.

## 20. Request size and content constraints

Current HTTP boundary:

- maximum request body: **1 MiB**
- JSON object required
- UTF-8 JSON decoding
- `Content-Type` must include `application/json`

The SDK should enforce useful client-side bounds where safe, but server validation remains authoritative.

## 21. Compatibility guarantees

Current repository guarantees:

- API version is explicitly **1.1** at the HTTP boundary.
- Platform package declares version **1.1.0**.
- Python support is **3.12 through 3.14** for the current repository.
- Current CI validates Python 3.12, 3.13 and 3.14.
- Current main commit `caaeb7a9b3689d665a61e0b2b014282f939d134c` has a successful CI run.
- No open pull requests or issues were found at audit time.
- The Platform roadmap defines M13 as the stable public consumer/domain SDK surface, but the existing `packages/sdk` is an internal/domain composition surface rather than this planned network client.

### What is not yet guaranteed

The repository does **not yet establish** a public SDK compatibility promise for:

- a separate PyPI client package;
- REST resource paths;
- OpenAPI compatibility;
- generated models;
- pagination;
- streaming;
- approval decision APIs;
- remote tool execution;
- stable public error schemas beyond the current minimal HTTP envelope;
- durable idempotency semantics across deployment restarts;
- distributed exactly-once effects.

These must not be implied by SDK v0.1 documentation.

## 22. SDK v0.1 recommended public surface

The first external client SDK should map only to currently implemented remote operations:

```python
client.health()
client.principal.get()
client.agents.list()
client.capabilities.list(agent_id)
client.runs.create(task_id, agent_id, intent)
client.runs.cancel(run_id)
client.approvals.request(run_id, action, resource, reason)
client.runs.events(run_id)
client.runs.evidence(run_id)
```

Plus transport-level configuration:

```python
AgentPlatform(
    base_url=...,
    bearer_token=...,
    api_version="1.1",
    timeout=...,
)
```

The exact Python naming may change during SDK implementation; the **operation semantics** above are the contract baseline.

## 23. Explicitly deferred SDK operations

The following should remain deferred until the Platform exposes versioned HTTP contracts:

- `runs.get`
- `runs.wait`
- `approvals.get`
- `approvals.approve`
- `approvals.reject`
- `approvals.cancel`
- `tools.list`
- `tools.execute`
- `events.stream`
- `evidence.get`
- evidence content retrieval
- pagination
- webhook/event subscriptions

This prevents the SDK from becoming a second, invented Platform API.

## 24. SDK boundary invariant

The external SDK is a **client-side contract layer**, not an authority engine.

It may:

- construct requests;
- validate developer inputs;
- serialize/deserialize;
- authenticate transport;
- propagate correlation metadata;
- classify errors;
- provide retries only where contractually safe;
- expose typed models.

It must not independently decide:

- authorization;
- policy;
- approval;
- tenant authority;
- tool permission;
- secret access;
- sandbox permission;
- evidence validity;
- execution authority.

Those remain Platform responsibilities.

## 25. Security rationale

This contract deliberately keeps the remote surface narrow. Current agent-security guidance continues to emphasize identity and privilege abuse, tool misuse, excessive agency, supply-chain risks, unexpected code execution and human-agent trust exploitation as important agentic risks. The SDK therefore must not create a side channel around the Platform's governed execution boundary.

## 26. Implementation acceptance criteria for SDK v0.1

SDK v0.1 is not complete until:

1. It communicates only through the versioned Platform API boundary.
2. It sends API version 1.1.
3. It uses bearer credentials without assuming a credential format.
4. It generates/propagates normalized request IDs.
5. It preserves idempotency semantics for consequential operations.
6. It exposes typed request/response models for the current operation set.
7. It maps stable HTTP errors without leaking credentials or internals.
8. It has contract tests against the actual reference Platform gateway.
9. It has integration tests using real HTTP.
10. It does not expose unimplemented remote operations.
11. Its documentation distinguishes the public network SDK from the repository's existing internal/domain SDK.
12. Its compatibility policy explicitly separates SDK version from Platform API version.
13. CI validates packaging, tests, typing, linting and security gates.
14. A reference agent can use the SDK without importing Platform internals.

## 27. Source-of-truth hierarchy

For future SDK work, resolve discrepancies in this order:

1. Current executable Platform implementation.
2. Current executable API/conformance tests.
3. This SDK v0.1 contract.
4. `docs/ARCHITECTURE.md` and `docs/ROADMAP.md`.
5. Current API/integration architecture documentation.
6. Historical ADRs and milestone status documents.

A change to the server API that affects SDK compatibility must update the Platform contract, tests and SDK compatibility documentation together.

---

**Audit conclusion:** the current Platform has a real, test-backed v1.1 operation gateway, but it does **not** yet have the resource-oriented external HTTP API surface previously assumed in generic SDK planning. The correct SDK v0.1 is therefore a narrow, typed client for the existing v1.1 operation envelope. Expanding the SDK beyond this contract should follow implementation of corresponding versioned Platform endpoints rather than inventing client-side abstractions.
