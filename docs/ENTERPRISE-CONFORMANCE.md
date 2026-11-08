# Enterprise Conformance

The platform's enterprise claim is based on executable controls rather than milestone labels alone.

## Canonical sequence

M0 -> M1 -> M2 -> M3 -> M4 -> M5 -> M6 -> M7 -> M8 -> M9 -> M10 -> M11 -> M12 -> M13 -> M14

M14 closes the canonical roadmap. M15-M29 are complete repository-level enterprise evolution phases.

## Post-M14 conformance

- **M15:** durable outbox/recovery contracts and worker ownership leases.
- **M16:** verified federated identity claims and execution-scoped secret handles.
- **M17:** secure remote-agent discovery metadata and authority-attenuating delegation.
- **M18:** tenant/run/execution/trace correlation, SLO measurement and safety-aware evaluation gates.
- **M19:** evidence-backed production acceptance and GA certification contract.
- **M20:** risk classification, runtime control hooks, tenant-bound resource registry, attestation claims, cryptographic metadata and compliance traceability.
- **M21:** evidence-backed readiness contract for the external production dependency boundary.
- **M22:** token validation, sender-constraint metadata, key lifecycle and attestation revocation contracts.
- **M23:** registry lifecycle, compatibility, provenance, digest and revocation controls.
- **M24:** executable adversarial security regression corpus and fail-closed release gate.
- **M25:** recovery objectives, failure-mode drills and RTO/RPO release gate.
- **M26:** capacity envelopes and tenant economic quotas for admission governance.
- **M27:** error budgets, alert thresholds and evidence-backed incident records.
- **M28:** release provenance, SBOM/signature evidence and migration/rollback contracts.
- **M29:** independent-assurance report, scope, findings and final certification gate.

## Invariants

- Tenant identity is bound at request, task, run, model and tool boundaries.
- Authorization is evaluated outside model reasoning.
- Risk can constrain but never grant authority.
- Runtime control hooks can deny or require review but cannot bypass the authoritative execution boundary.
- Registry records describe lifecycle, compatibility and provenance; registration does not authorize use.
- Revoked resources are not usable.
- Attestation is time-bounded, revocable and cannot widen authority.
- Token issuer and audience are explicitly validated; nonce binding is enforced when requested.
- Sender-constraint metadata does not replace authorization.
- Key lifecycle state is explicit and private key material remains external.
- Adversarial evaluation never grants authority and a failed blocking case prevents release.
- Recovery evidence measures resilience and cannot be replaced by a green unit test alone.
- Capacity and quota controls constrain admission but do not grant authority.
- Error budgets and alerts provide operational signals; they do not grant execution authority.
- Release manifests bind source, artifact, SBOM, provenance and signature evidence; they do not authorize execution.
- Independent assurance does not manufacture evidence; assessor identity and evidence must come from the external engagement.
- High-risk or irreversible actions remain approval-gated.
- Tool and MCP calls are completely mediated against capability, action and resource.
- Model providers can be tenant/agent allowlisted and cannot exceed requested output budgets.
- Context excludes untrusted content by default and redacts secret-like material.
- Evidence is bounded, tenant-scoped and independently hash-verifiable.
- Trajectory is append-only in the reference store and hash-chain verifiable.
- Events are immutable, tenant-scoped and reject sensitive fields.
- Runtime state transitions and turn/tool budgets are enforced before consequential side effects.
- Remote interoperability cannot grant authority; consequential work re-enters the governed execution boundary.
- Evaluation does not grant authority.
- Domain SDKs remain consumers; domain products do not become platform dependencies.

## Production boundary

The repository provides a governed, provider-neutral core and reference adapters. Customer production deployment still requires real durable stores, secret management, approved model/tool providers, isolated execution infrastructure, telemetry backends, backup/restore, incident response, key management and operational SLOs.

M19-M29 make the evidence, readiness, trust, ecosystem-governance, adversarial-security, recovery, capacity, SRE, release and independent-assurance requirements explicit; they do not substitute test doubles for deployed infrastructure.

Conformance is enforced by CI on every pull request.

## Finalization

After M29, the finite engineering roadmap ends. New threats, standards, incidents and platform changes enter continuous enterprise assurance rather than new arbitrary numbered phases.


## Extensions dead-letter replay conformance — PR #195

The Platform integration now has an executable HIGH-risk replay contract with exact intent binding, explicit human approval, one-time approval consumption, idempotent retry behavior, and least-privilege downstream service-token scope. Negative tests cover absent approval verifier, event-intent substitution, and retry behavior without a second downstream side effect. The successful path verifies tenant, subject, audience, request ID and the sole `extensions:outbox:replay` scope in the minted JWT.

PR #195 merged as `a2cd923b7d187de2f0b983a169ea0f03ff96aa94`. Exact-head workflows passed on `f4ba45893cf0261deff58629ba964a24e28e953d`: CI (Python 3.12/3.13/3.14, PostgreSQL integration and TSIC), CodeQL [42457552627](https://github.com/LloydCoder/tinlance-agent-platform/actions/runs/42457552627), Secret Scan [42457552644](https://github.com/LloydCoder/tinlance-agent-platform/actions/runs/42457552644), Reference Agents [42457552676](https://github.com/LloydCoder/tinlance-agent-platform/actions/runs/42457552676), and R10 Certification [42457552736](https://github.com/LloydCoder/tinlance-agent-platform/actions/runs/42457552736). Exact-head CI is [42457552670](https://github.com/LloydCoder/tinlance-agent-platform/actions/runs/42457552670).

Post-merge checks passed on `a2cd923b7d187de2f0b983a169ea0f03ff96aa94`: CI [42457671532](https://github.com/LloydCoder/tinlance-agent-platform/actions/runs/42457671532), CodeQL [42457671552](https://github.com/LloydCoder/tinlance-agent-platform/actions/runs/42457671552), Secret Scan [42457671510](https://github.com/LloydCoder/tinlance-agent-platform/actions/runs/42457671510), Reference Agents [42457671509](https://github.com/LloydCoder/tinlance-agent-platform/actions/runs/42457671509), R10 Certification [42457671536](https://github.com/LloydCoder/tinlance-agent-platform/actions/runs/42457671536), and Supply Chain Attestation [42457671530](https://github.com/LloydCoder/tinlance-agent-platform/actions/runs/42457671530).

This is a merged integration contract, not evidence of a production-configured approval provider or a production Extensions endpoint deployment. Production must inject the durable, tenant-aware approval verifier, configure service-token signing/rotation, and complete live identity-provider, provider-delivery, operational, privacy and independent security reviews. External delivery remains at-least-once; do not describe it as exactly-once.
