# Enterprise Baseline

This document defines the boundary between enterprise-grade platform controls in the repository and deployment controls that must be supplied and verified by an operator.

## Enterprise control model

The Platform control chain is:

identity -> tenant -> authorization -> policy -> risk -> approval -> execution boundary -> evidence

Risk, registry metadata, attestation, evaluation results and external intelligence are control inputs or evidence; none can independently grant authority.

## Authority
- Principal identity is explicit.
- Tenant scope is immutable.
- Capabilities are not authority by themselves.
- Prohibited capabilities are never executable.
- Consequential tool execution re-authorizes immediately before the side effect.
- Child agents receive only subsets of parent authority.
- High-risk and irreversible actions can require explicit approval.

## Trust and cryptography
- Token issuer and audience are validated explicitly.
- Nonce binding is available where the protocol requires it.
- Sender-constraint metadata is treated as an additional trust input, not authorization.
- Key lifecycle states are explicit.
- Private key material and provider credentials remain external to the Platform contract layer.
- Agent/workload/artifact/runtime attestations are time-bounded and revocable.

## Registry and ecosystem
- Governed resources carry lifecycle, compatibility, digest and provenance metadata.
- Revoked resources are not usable.
- Registration does not authorize use.
- Remote interoperability cannot widen tenant or capability authority.

## Human control
- High-risk, irreversible, sensitive/restricted and broad-blast-radius actions pause for approval.
- Approval is bound to tenant, run, action and resource.
- Approval expires and fails closed.
- The execution path independently validates policy and approval instead of trusting an agent-produced approval claim.

## Isolation
- Governed sandbox availability is mandatory.
- Commands and workspace paths are allowlisted.
- Network access is denied by default where the sandbox policy requires it.
- Host-sensitive paths are rejected.
- Production supervisors must additionally enforce CPU, memory, disk, process and output ceilings.

## Reliability and performance
- Durable execution uses outbox/lease/recovery semantics.
- Recovery drills record RTO/RPO evidence.
- Capacity gates record throughput, p95/p99 latency and concurrency evidence.
- Tenant quotas constrain concurrency, tool calls, token units and cost units.
- Error budgets quantify observed service failure against explicit SLO targets.

## Security and adversarial evaluation
- Safety-critical regressions fail evaluation gates.
- Agent-specific attack classes are version controlled as security regression cases.
- Goal hijacking, tool misuse, identity/privilege abuse, memory poisoning, inter-agent attacks, cascading failures, trust exploitation, data exfiltration, sandbox escape and resource exhaustion are explicit test classes.
- Evaluation results never grant runtime authority.

## Observability and incident evidence
- Telemetry carries correlation metadata such as tenant, run, trace and outcome.
- Sensitive prompt/tool content is not required for telemetry.
- Error budgets and alerts are operational signals.
- Incident records require evidence references.
- Production deployments should map platform signals to OpenTelemetry conventions and retain security-relevant traces/events according to organizational policy.

## Supply chain and release
- CI pins GitHub Actions by immutable commit reference.
- Dependency vulnerabilities are checked with pip-audit.
- CI generates a CycloneDX SBOM.
- Release artifacts are signed with Sigstore.
- Release manifests bind source revision, artifact digest, SBOM, provenance and signature evidence.
- Upgrade plans carry migration and rollback references.

## Independent assurance

M29 defines the final assurance evidence contract. An assurance report must identify an assessor, scope, findings and evidence, and cannot certify while findings remain open. The repository does not claim that an external assessor has performed the engagement; that evidence must be supplied by the actual assurance activity.

## Production acceptance checklist

A production deployment is not accepted until the operator has verified:

- [ ] Dedicated non-superuser application database role with no BYPASSRLS.
- [ ] PostgreSQL migrations and isolation/integrity tests pass in the target environment.
- [ ] Durable repositories and transactional outbox/recovery strategy are deployed.
- [ ] External secret manager is deployed, rotated and audited.
- [ ] Model/tool/MCP providers use least-privilege credentials and scopes.
- [ ] Linux sandbox behavior is verified on the production runtime.
- [ ] Process, CPU, memory, disk and output limits are enforced by the supervisor.
- [ ] OpenTelemetry collector/exporter and alerting are configured.
- [ ] Backups are enabled and restore drills have succeeded.
- [ ] Incident-response and security-event retention policies are approved.
- [ ] Domain SDK consumers pass compatibility/conformance tests.
- [ ] FAS/FAS-Bench/FDSE integration tests run in their own repositories.
- [ ] Security ownership and operational escalation are assigned.
- [ ] Deployment configuration is reviewed for tenant isolation and secret leakage.

## Current repository posture

CI can prove repository behavior and build/release controls. It cannot prove that an external PostgreSQL cluster, secret manager, telemetry backend, production supervisor, backup system or incident-response process has been deployed correctly.

Therefore:

> **Enterprise-grade repository controls are not a claim of completed production infrastructure.**

The acceptance checklist above is the final deployment gate.

## External alignment

The baseline tracks current NIST and OWASP agent-security guidance, OAuth token-protection practices, OpenTelemetry conventions and software-supply-chain provenance guidance. These sources inform the baseline; they do not replace executable tests or operator/independent assurance evidence.
