# Enterprise Baseline

This document defines the boundary between **enterprise-grade platform controls in the repository** and **deployment controls that must be supplied and verified by an operator**.

## Security references

The baseline tracks current agent-security guidance from NIST and OWASP around agent identity, authorization, least privilege, human approval, isolation, auditability, prompt-injection resistance, memory protection, cost controls and adversarial evaluation.

The platform therefore treats identity, policy, approval and execution as independent control points rather than relying on model confidence or model output.

## Enterprise controls

### Authority
- Principal identity is explicit.
- Tenant scope is immutable.
- Capabilities are not authority by themselves.
- Prohibited capabilities are never executable.
- Consequential tool execution re-authorizes immediately before the side effect.
- Child agents receive only subsets of parent authority.

### Human control
- High-risk, irreversible, sensitive/restricted and broad-blast-radius actions pause for approval.
- Approval is bound to tenant, run, action and resource.
- Approval expires and fails closed.
- The execution path independently validates policy and approval instead of trusting an agent-produced approval claim.

### Isolation
- Governed sandbox availability is mandatory.
- Commands and workspace paths are allowlisted.
- Network access is denied by default where the sandbox policy requires it.
- Host-sensitive paths are rejected.
- The reference Linux/Bubblewrap adapter fails closed when required isolation cannot be established.
- Production supervisors must additionally enforce CPU, memory, disk, process and output ceilings.

### Data
- Memory is tenant scoped.
- Untrusted context is excluded by default.
- Secret-like material is redacted.
- Secrets resolve through execution-only handles.
- Evidence/audit records carry tenant/run attribution without requiring sensitive payloads.

### Persistence
- PostgreSQL migrations enforce tenant RLS and cross-tenant integrity.
- Evidence, trajectory and audit surfaces are append-oriented by policy and database grants.
- RLS is defense in depth and does not replace application authorization.

### Observability
- Telemetry carries useful correlation metadata such as tenant, run, trace and outcome.
- Sensitive prompt/tool content is not required for telemetry.
- Production deployments should map platform signals to OpenTelemetry conventions and retain security-relevant traces/events according to organizational policy.

### Evaluation
- Safety-critical regressions fail evaluation gates.
- Adversarial and failure-path cases are version controlled.
- Evaluation results never grant runtime authority.

### Supply chain
- CI pins GitHub Actions by immutable commit reference.
- Dependency vulnerabilities are checked with pip-audit.
- CI generates a CycloneDX SBOM.
- Release artifacts are signed with Sigstore.
- Dependency/provider additions require architectural review where they cross authority boundaries.

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

The repository's reference execution path enforces real wall-clock deadlines and the POSIX sandbox adapter supervises process groups with resource ceilings and timeout handling.

CI can prove repository behavior and build/release controls. It cannot prove that an external PostgreSQL cluster, secret manager, telemetry backend, production supervisor, backup system or incident-response process has been deployed correctly.

Therefore:

> **Enterprise-grade repository controls are not a claim of completed production infrastructure.**

The acceptance checklist above is the final deployment gate.

## External alignment

NIST's 2026 agent initiative emphasizes secure, interoperable agent ecosystems and agent identity/security. OWASP's current agent guidance emphasizes least privilege, per-tool authorization, high-impact human approval, exact approval binding, isolation, cost/tool-chain limits, audit trails and adversarial testing. OpenTelemetry provides common semantic conventions for correlated application and GenAI telemetry.

These sources inform the baseline; they do not replace the repository's executable tests or the operator's production acceptance process.
