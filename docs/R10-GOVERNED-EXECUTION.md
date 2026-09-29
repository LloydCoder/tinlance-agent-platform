# R10 — Governed Execution Contract

**Contract:** `governed-execution.v1`  
**Authority:** Tinlance Agent Platform  
**Client:** Tinlance Agent Platform SDK  
**Status:** implemented in the reference Platform boundary; deployment adapters remain explicit

## Purpose

R10 is the Platform's authoritative consequential-action boundary. Agents can propose actions, but they cannot authorize or execute them directly. The SDK transports typed requests; the Platform binds identity, tenant, capability, policy, approval, limits, evidence and audit before invoking a registered tool.

The design follows current agent-security guidance that emphasizes explicit identity/authorization, runtime enforcement, least privilege, human approval for high-impact actions, execution containment, adaptive budgets and auditable control paths. NIST's 2026 agent identity work specifically highlights identification, authorization, auditing, non-repudiation and prompt-injection controls, while OWASP's 2026 agentic guidance highlights tool misuse, identity/privilege abuse and unexpected code execution. See the project references below.

## Public operations

### `tools.execute`

The SDK request contains:

- `contract_version=governed-execution.v1`
- request ID
- idempotency key
- tenant/principal/agent/run identity
- capability and version
- tool and version
- action/resource
- normalized input
- timeout/tool-call budget
- risk/reversibility/data classification
- sandbox/evidence requirements
- optional approval ID

Security-sensitive identity is derived from the authenticated principal and checked against the registered agent. Client assertions do not grant authority.

### `approvals.decide`

Approval decisions are authenticated, tenant-scoped and one-time. The approval binds to the requesting run, action and resource and can optionally bind to an execution fingerprint. The reference implementation rejects requester self-approval and rejects decisions against non-pending approvals.

### `executions.get`

Execution status is tenant-scoped and returns the terminal/non-terminal R10 state plus safe result references.

## Execution state

`requested → waiting_approval/authorized → running → completed|failed|timed_out|cancelled|denied|budget_exceeded|outcome_unknown`

`outcome_unknown` is intentionally non-retryable by default: the Platform cannot safely repeat a consequential operation when it cannot establish whether the prior operation completed.

## Identity binding

An immutable execution identity binds:

- execution ID
- tenant
- authenticated principal
- agent
- parent run
- capability
- tool
- policy decision
- approval
- request
- trace

Changing any material security context requires a new authorization/execution intent.

## Policy

Policy is evaluated before consequential execution. The existing deterministic policy returns explicit allow/deny/approval-required outcomes. Policy failure is not converted to allow.

Tool registrations also carry a risk ceiling, capability, version, timeout, tool-call ceiling, sandbox requirement and evidence requirement. A request cannot exceed the registered ceiling.

## Approval

Approval lifecycle:

`PENDING → APPROVED|REJECTED|EXPIRED|CANCELLED`

`APPROVED → CONSUMED`

A consumed approval cannot be reused. The approval service uses locking for the reference implementation; distributed deployments must provide transactional/optimistic concurrency semantics in the durable adapter.

## Idempotency

Consequential calls use `Idempotency-Key`. The Platform derives a canonical SHA-256 fingerprint over security-relevant intent rather than trusting the client to define equivalence.

The same tenant + key + fingerprint returns the original result. Reusing the key for a different fingerprint is a conflict. An unresolved in-flight/approval-gated request remains resumable with the same intent; an already ambiguous execution is represented as `outcome_unknown` and is never silently replayed.

The repository includes both an in-memory conformance implementation and a durable SQLite implementation. The SQLite provider uses a unique `(tenant_id, idempotency_key)` primary key and transactional claim/complete operations. SQLite is suitable for a durable single-host deployment; distributed production deployments should inject a transactional Postgres-equivalent provider with the same repository contract. The Platform never silently falls back from a required durable provider to process memory.

## Budgets and timeouts

R10 enforces the registered maximum tool-call budget and computes an effective timeout bounded by the client request, tool registration and Platform maximum.

The reference boundary measures elapsed execution and represents a late/ambiguous completion as `outcome_unknown`. Hard process/container cancellation remains an execution-adapter responsibility; production tool adapters MUST provide an authoritative timeout/cancellation primitive before advertising hard timeout enforcement.

No agent can increase a registered ceiling.

## Sandbox

A tool may require a sandbox. R10 fails closed when a required sandbox provider is unavailable. The sandbox provider is injected into the authoritative execution service; the agent cannot disable a mandatory sandbox.

The reference gateway does not pretend that its deterministic echo tool is an OS sandbox. Production deployments must inject the Platform's actual isolation provider for tools that require filesystem/process/network containment.

## Secrets

Secret access is represented by a Platform-owned gate. The agent does not receive authority merely by requesting a secret. Production secret providers must bind access to tenant, principal, agent, capability and execution, and must redact secrets from evidence, audit records, logs and traces.

## Evidence

Tool output that is required to be evidenced is committed through the existing evidence store and bound to both the parent run and execution ID. The store records a SHA-256 content digest and verifies it on read/verification.

The execution service does not treat LLM text as authoritative evidence.

## Audit

R10 emits lifecycle/security events including:

- execution requested
- identity bound
- policy evaluated
- approval required/decided/consumed
- budget reserved
- sandbox started
- execution started/completed/failed/timed out
- evidence committed
- execution finalized
- authorization denied

Execution events retain the parent run as the event partition key and include the execution ID for causal reconstruction.

## Fail-closed rules

Authentication/identity/tenant/capability/policy/approval/sandbox/evidence/audit failures do not silently become authorization. Unknown execution outcome never triggers an automatic consequential retry.

## External standards considered

- NIST 2026 software-agent identity and authorization work
- NIST IR 8587 (2026) for token/assertion protection and lifecycle controls
- OWASP Top 10 for Agentic Applications 2026
- OWASP Agent Control Standard (2026)
- RFC 9449 DPoP where sender-constrained OAuth tokens are applicable
- current MCP security/authorization model where MCP is deployed
- OpenTelemetry semantic conventions for correlated events/spans

DPoP is not required by `governed-execution.v1` itself because the current reference authentication contract uses an injected bearer-token resolver. Deployments using OAuth bearer tokens should evaluate sender-constrained access tokens and replay-resistant proofs rather than treating DPoP as an authorization mechanism.

## Deployment truth

The reference Platform implementation is intentionally explicit about provider boundaries:

| Control | Reference implementation | Production requirement |
|---|---|---|
| identity binding | implemented | real authenticated identity provider |
| tenant isolation | enforced in service | durable store-level tenant constraints |
| policy | deterministic | authoritative policy provider |
| approval | in-memory reference | durable transactional approval store |
| idempotency | in-memory reference | durable uniqueness/transactional store |
| budget | registered tool-call ceiling | distributed reservation/accounting provider |
| timeout | elapsed-time + ambiguity semantics | hard cancellation-capable execution adapter |
| sandbox | required-provider gate | real isolation provider |
| secrets | injected authorization gate | real scoped secret broker |
| evidence | SHA-256 + execution binding | durable evidence store |
| audit | correlated event store | durable/immutable audit pipeline |

R10 is complete as a contract and reference authority boundary only where these distinctions remain explicit; a deployment must not advertise provider capabilities it has not actually supplied.

## Security references

- NIST: Accelerating the Adoption of Software and Artificial Intelligence Agent Identity and Authorization
- NIST IR 8587: Protecting Tokens and Assertions from Forgery, Theft, and Misuse
- OWASP Top 10 for Agentic Applications 2026
- OWASP Agent Control Standard
- RFC 9449: OAuth 2.0 Demonstrating Proof of Possession
