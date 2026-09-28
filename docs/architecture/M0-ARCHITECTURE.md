# M0 Architecture Baseline

## Control flow invariant

principal -> request context -> capability request -> authorization -> policy -> approval/risk gate -> execution boundary -> evidence/audit/telemetry

No agent may invoke an external side effect directly.

## Planes
- Control: identity, tenancy, authorization, policy, approvals, budgets and registries.
- Execution: runtime, orchestration, model/tool gateways, secrets and sandbox.
- Evidence: events, trajectory, provenance, audit, evaluation and observability.

## Layering

contracts -> kernel -> services -> adapters -> apps

Lower layers cannot import domain-specific code from higher layers.

## Technology decisions

Python 3.12–3.14; modular monolith first; PostgreSQL control-plane store; database RLS as defense in depth; provider-neutral ports; OpenTelemetry-compatible boundary; risk-tiered sandbox selection.

## Explicit non-decisions

Kubernetes, Kafka, graph databases, service meshes and dedicated workflow vendors are not M0 requirements. They must be justified by operational evidence.

## Domain boundary

FDSE, TADS, ThreatFade, ReconOS, FadeReach and future domains register against stable platform contracts and do not own generic identity, authorization, policy, runtime or gateway controls.
