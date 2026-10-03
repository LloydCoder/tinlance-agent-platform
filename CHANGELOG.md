# Changelog

## 2026-10-03 — Enterprise Evolution M25

- Added recovery objectives and failure-mode drill contracts for worker crash, database/queue outage, network partition, duplicate delivery, provider timeout and regional failure.
- Added RTO/RPO evidence requirements and a fail-closed recovery gate.
- Reconciled disaster-recovery documentation to distinguish measured readiness from deployed infrastructure.

## 2026-10-03 — Enterprise Evolution M24

- Added executable adversarial-agent security regression cases.
- Added attack-class coverage for goal hijacking, tool misuse, identity/privilege abuse, memory poisoning, inter-agent attacks, cascading failures, trust exploitation, data exfiltration, sandbox escape and resource exhaustion.
- Added a fail-closed release gate requiring evidence for every blocking regression case.

## 2026-10-03 — Enterprise Evolution M23

- Added registry lifecycle, compatibility and provenance contracts.
- Added algorithm-qualified resource digests and fail-closed protocol compatibility checks.
- Added explicit registry revocation behavior without creating an authorization bypass.

## 2026-10-03 — Enterprise Evolution M22

- Added token validation and sender-constraint metadata contracts.
- Added explicit cryptographic key lifecycle states and one-active-version validation.
- Added attestation trust expiry and revocation contracts.
- Reconciled enterprise identity and trust documentation with current token protection guidance.

## 2026-10-03 — Enterprise Evolution M21

- Added explicit production dependency readiness contracts covering database, outbox, secret manager, sandbox, telemetry, backup, incident response and operational ownership.
- Added evidence requirements for every verified production dependency.
- Reconciled the deployment contract to distinguish readiness certification from infrastructure provisioning.

## 2026-10-03 — Enterprise Control Expansion M20

- Added provider-neutral risk classification contracts for consequential action severity and approval thresholds.
- Added runtime control-hook contracts that fail closed without creating a second authority path.
- Added tenant-bound resource registry contracts for governed agents, tools, MCP servers, models, policies, runtimes and remote agents.
- Added time-bounded agent/workload/artifact/runtime attestation contracts.
- Added cryptographic key-reference and signature-envelope contracts without storing key material.
- Added control-to-test-to-evidence compliance mappings.
- Reconciled architecture, enterprise conformance and release-readiness documentation.

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
