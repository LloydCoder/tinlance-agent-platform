# Tinlance Web Intelligence integration

## Authority and trust boundaries

Tinlance Agent Platform remains the only authority for identity, authorization, risk policy,
human approval, execution evidence, and audit. Tinlance Web Intelligence (TWI) is a downstream
acquisition service. Its HTTP API is not exposed directly to untrusted MCP callers.

The Platform integration is implemented by:

- `TWI_MCP_TOOL_DEFINITIONS`: versioned MCP operation descriptions exposed by the Platform's
  existing `MCPProtocolService`.
- `TWIAPIHandler`: dispatches only registered `twi.*` operations through
  `MCPToolGateway`; all other operations are delegated to the existing API handler.
- `TWIHTTPTransport`: calls TWI's HTTP API with bounded responses, finite timeouts, HTTPS in
  production, and redirects disabled.
- `TWIServiceTokenIssuer`: an injected Platform identity adapter that mints a short-lived token
  with the TWI API audience, caller tenant/subject, and only the required TWI scope.

The adapter never forwards the inbound MCP bearer token to TWI. TWI receives a Platform-issued
audience-bound token. The service-token issuer must be backed by the Platform identity authority;
a static bearer token or caller-supplied identity claims are not an acceptable production substitute.

## Governed operations

| MCP tool | Downstream operation | Required downstream scope | Platform behavior |
| --- | --- | --- | --- |
| `twi_search` | `POST /v1/jobs` (`kind=search`) | `twi:search` | Open-world acquisition policy and idempotent submission |
| `twi_fetch` | `POST /v1/jobs` (`kind=fetch`) | `twi:fetch` | URL acquisition policy and idempotent submission |
| `twi_browser_navigate` | `POST /v1/jobs` (`kind=browser`) | `twi:browser` | Isolated browser policy, egress controls, resource budgets |
| `twi_job_read` | `GET /v1/jobs/{job_id}` | `twi:jobs:read` | Tenant/subject-scoped read |
| `twi_job_cancel` | `POST /v1/jobs/{job_id}/cancel` | `twi:jobs:cancel` | Authenticated cancellation of the caller's job |
| `twi_evidence_export` | `GET /v1/jobs/{job_id}/evidence` | `twi:evidence:export` | Tenant/subject-scoped evidence export; MCP response is bounded to 1 MiB, larger packages use the authenticated HTTP API |
| `twi_monitor_create` | `POST /v1/monitors` | `twi:monitors:write` | Idempotent monitor creation using TWI URL safety policy |
| `twi_monitor_read` | `GET /v1/monitors/{monitor_id}` | `twi:monitors:read` | Tenant/subject-scoped monitor read |
| `twi_monitor_run` | `POST /v1/monitors/{monitor_id}/runs` | `twi:monitors:write` | Explicit idempotent capture enqueue; Agent OS owns recurrence |
| `twi_monitor_pause` | `POST /v1/monitors/{monitor_id}/pause` | `twi:monitors:write` | Pause future run enqueues |
| `twi_monitor_resume` | `POST /v1/monitors/{monitor_id}/resume` | `twi:monitors:write` | Resume a paused monitor |
| `twi_monitor_delete` | `DELETE /v1/monitors/{monitor_id}` | `twi:monitors:delete` | Destructive redaction/tombstone; high-risk, exact-intent human approval and idempotency key required |
| `twi_research_verify` | `POST /v1/research/verify` | `twi:research:verify` | Verifies captured-source provenance and exact excerpt matches; not factual truth |
| `twi_world_intelligence_export` | `POST /v1/integrations/world-intelligence/exports` | `twi:observations:export` | High-risk consequential operation; requires a bound, one-time human approval and idempotency key |
| `twi_world_intelligence_export_status` | `GET /v1/integrations/world-intelligence/exports/{event_id}` | `twi:observations:export:read` | Tenant/subject-scoped read |

The MCP tool's Platform capability and risk metadata are authoritative. A caller cannot downgrade a
registered high-risk export or monitor deletion to low risk. Export is denied until the approval verifier validates the
approval against the exact tenant, run, action, resource, and intent fingerprint.

## Approval binding for source-evidence export

The export input includes `run_id`, `approval_id`, `intent_fingerprint`, and
`idempotency_key`. These are Platform control fields. `TWIAPIHandler` validates the UUIDs,
recomputes the intent fingerprint from the authenticated tenant, subject, run, registered tool
capability, action, resource, and complete export arguments, and rejects a mismatch before network
access. The transport strips the Platform-only fields from the downstream HTTP body.

The approval request must be created through the Platform ApprovalService with the same
`intent_fingerprint`. The approval verifier must be the Platform-owned one-time approval service;
a caller-provided boolean or approval claim is not accepted. The exported record remains candidate
source evidence in World Intelligence, not a canonical observation or a statement of truth.

## Registration

Compose the integration at the Platform application boundary using its existing trusted components:

1. Construct `TWIHTTPTransport` with a configured TWI origin, the exact TWI audience, and the
   Platform identity token issuer.
2. Construct `MCPToolGateway` with that transport and call `register_twi_tools(gateway)`.
3. Wrap the normal Platform API handler in `TWIAPIHandler`, injecting the same gateway and the
   Platform ApprovalService verifier.
4. Construct `AgentPlatformAPI` with the wrapped handler and register
   `TWI_MCP_TOOL_DEFINITIONS` in the existing `MCPProtocolService`.

Production configuration must use HTTPS, trusted service discovery/network policy, the TWI API
audience configured in its verifier, short-lived scoped downstream tokens, and a secret-manager-backed
identity provider. Loopback HTTP is available only when explicitly enabled for local development.

## Verification

The Platform tests cover token audience/scope minting, tenant and subject binding, trace propagation,
strict export intent fingerprints, high-risk approval enforcement, idempotency, redirect rejection,
and fail-closed transport errors. These are reference integration tests; they do not by themselves
prove that a production deployment has been wired or deployed.


## KMS-backed Platform service tokens

The Platform identity package provides `KMSRS256Signer` and `PlatformServiceTokenIssuer`.
The issuer implements the service-token protocol consumed by both `TWIHTTPTransport` and
`WorldIntelligenceHTTPTransport`. It emits short-lived RS256 access tokens with the strict
`typ=at+jwt` header and the claims required by `JWKSIdentityVerifier`: issuer, audience,
subject, tenant, principal type, client ID, token ID, issued-at, expiry and delegated scope.
World Intelligence calls additionally carry a signed `purpose` claim.

The signer delegates RS256 signing to an asymmetric AWS KMS key. The key must use
`SIGN_VERIFY`, an RSA key spec, and `RSASSA_PKCS1_V1_5_SHA_256`. The runtime identity needs
only `kms:GetPublicKey` and `kms:Sign` on the specific key ARN. The private key is never
exported. Publish `signer.jwks()` at `/.well-known/jwks.json` by passing the signer as the
`jwks_provider` argument to the Platform HTTP boundary. The endpoint returns public RSA key
parameters only, validates the document, and uses a short cache lifetime. Configure previous
public key IDs through `verification_key_ids` during rotation so tokens signed by the retiring
key remain verifiable during the overlap window.

The canonical downstream audiences are `tinlance-web-intelligence` for TWI and
`world-intelligence` for World Intelligence. These values must match each resource server's
strict JWT verifier configuration exactly. Do not use a generic audience or accept arbitrary
audiences supplied by a caller.

This issuer is the **Platform-to-service** token-signing component. It does not implement
interactive human sign-in, external identity-provider federation, tenant membership resolution,
or policy evaluation. Those must happen before this issuer is called. The supplied tenant,
subject and scopes must come from a verified Platform principal and an authorization decision;
the issuer itself is not an authorization service. A real deployment still requires a trusted
inbound identity provider, server-side tenant mapping, production revocation storage, key
rotation operations and an HTTPS deployment of the JWKS endpoint. See
`docs/adr/ADR-0042-kms-backed-platform-service-tokens.md`.

## Monitor and evidence-export boundaries

Monitor operations are explicit requests only. TWI stores monitor definitions and bounded change observations; Agent OS owns recurrence. Monitor deletion requires its own twi:monitors:delete scope and a one-time approval bound to the exact tenant, subject, run, operation, resource and argument fingerprint. Pause/resume do not delete monitor data.

The evidence-export endpoint returns application/vnd.tinlance.twi-evidence+json. The Platform MCP transport intentionally enforces the protocol's 1 MiB response ceiling. Packages larger than that ceiling fail closed through MCP and must be retrieved using the authenticated TWI HTTP API with the same tenant/subject scope; do not raise the MCP response limit to accommodate arbitrary artifact sizes.
