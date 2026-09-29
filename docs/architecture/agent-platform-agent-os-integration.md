# Agent Platform ↔ Agentic OS Integration Contract

## Status
Canonical integration contract — API v1.1.

This document defines the boundary between Tinlance Agent Platform and Tinlance Agentic OS. Executable tests and the platform authority invariants remain authoritative for implementation.

## Architectural ownership

| Capability | Agent Platform | Agentic OS |
|---|---|---|
| Principal identity | Authoritative | Consumes |
| Tenant authority | Authoritative | Propagates |
| Authentication | Authoritative boundary | Supplies credential |
| Authorization | Authoritative | Requests |
| Policy | Authoritative | Presents/configures intent |
| Human approval | Authoritative | Presents/coordinates |
| Governed execution | Authoritative | Requests |
| Model/tool/MCP execution | Authoritative | Requests |
| Sandbox/security boundary | Authoritative | Requests |
| Secrets | Authoritative | Never receives raw secret authority |
| Budgets/quotas | Authoritative | Consumes status |
| Evidence/audit | Authoritative | Displays opaque references |
| Platform events | Authoritative | Consumes |
| Sessions | Run context only | Authoritative |
| Tasks/workflows | Execution contract only | Authoritative |
| Workspace UX | No | Authoritative |
| Applications/extensions | No | Authoritative |

The OS is not a second authorization kernel. The Platform is not the OS shell or application environment.

## Trust and authority flow

human/service → Agent OS session/task/workflow → authenticated Platform request → principal and immutable tenant binding → Platform authorization/policy → approval when required → governed execution boundary → tool/MCP/model/sandbox side effect → evidence and audit → opaque result/reference to Agent OS.

Model output, retrieved content, tool output, memory, extension data and peer-agent messages are untrusted inputs. None can create authority.

## Wire envelope

Endpoint: POST /v1/agent-platform

Required headers:
- Authorization: Bearer credential
- Content-Type: application/json
- X-Tinlance-API-Version: 1.1
- X-Request-ID: non-empty normalized identifier

Optional header: traceparent using W3C Trace Context syntax.

Request body fields:
- tenant_id
- subject_id
- operation
- payload

The body identity is an assertion that must match the authenticated principal. It is never accepted as an authority source.

The reference HTTP boundary rejects incompatible API versions, malformed trace context, missing authentication, tenant/subject mismatch, oversized bodies, non-JSON requests and malformed request envelopes.

Response fields:
- status: ok or accepted
- payload: operation-specific object

Responses carry X-Tinlance-API-Version: 1.1 and stable error classes without internal exception details.

## Operation contract

Current v1.1 operations:
- health
- principal.get
- agents.list
- capabilities.list
- runs.create
- runs.cancel
- approvals.request
- runs.events
- runs.evidence

Operations are versioned contracts, not permission grants. Their authorization semantics remain Platform-owned.

## Identity model

A request is bound to tenant, authenticated subject, request ID and optional trace context.

Agent OS must not manufacture or widen tenant or subject authority. A production resolver must validate bearer credentials using the deployment identity system, including issuer, audience, signature, expiry and lifecycle controls appropriate to that deployment.

## Session, task and run separation

- OS Session = interaction/lifecycle context.
- OS Task = unit of intent.
- Platform Run = governed execution instance.

A session may contain many tasks; a task may produce zero, one or many Platform runs.

## Approval boundary

Agent OS receives an opaque approval reference. Approval validity, expiry, actor binding, tenant binding, action/resource binding and final authorization remain Platform responsibilities.

For consequential actions, the execution boundary must re-authorize immediately before the side effect. An approval reference is not itself permission to bypass that check.

Future contract extensions should bind approval to normalized consequential parameters or a cryptographic argument digest where arguments materially affect the side effect.

## Events and evidence

Platform event/evidence identifiers are opaque references. Agent OS may correlate them with session/task/workflow IDs, but it must not rewrite Platform evidence authority.

Sensitive prompts, credentials and secret values must not be copied into OS telemetry merely to improve correlation.

## Reliability

Agent OS automatically retries only operations whose contract is idempotent. Consequential run creation, cancellation and approval requests now use deterministic request IDs derived from the operation and canonical payload, so transport retries and process restarts reuse the same replay key. Exactly-once side effects still require durable Platform-side idempotency and recovery.

The request ID can support server-side idempotency, but a production deployment must provide durable idempotency and recovery before claiming exactly-once side effects.

## Production boundary

The repository HTTP server is a reference contract boundary. Production must supply hardened TLS or secure RPC transport, standards-based credential validation, short-lived/scoped credentials, durable Platform repositories, durable idempotency/recovery, production authorization/policy services, isolated execution infrastructure, secret management, telemetry/audit retention, monitoring and incident response.

## Security references

The architecture is informed by NIST 2026 agent identity/authorization work and OWASP Top 10 for Agentic Applications 2026. NIST identifies agent identification, authorization, auditing and non-repudiation as dedicated control areas; OWASP provides an agent-specific threat taxonomy. MCP's July 2026 specification also hardens authorization and supports stateless operation, reinforcing explicit request identity and gateway-level authorization.

## Non-goals

Agent OS is not an authorization engine, policy engine, sandbox, secret manager, evidence authority, model provider, MCP registry, or hosted fleet-control plane. Agent Platform is not dependent on Agent OS.