# Tinlance Agent Platform

Tinlance Agent Platform is the governed execution substrate beneath Tinlance Agentic OS. It owns identity, tenancy, authorization, policy, approval, runtime, model/tool/MCP mediation, sandbox, secrets, budgets, evidence, audit and governed execution. Domain products consume stable contracts and SDK surfaces; they do not become platform dependencies.

## Enterprise evolution

The canonical M0-M14 roadmap and the post-M14 M15-M29 enterprise engineering sequence are complete at the repository level:

| Phase | Focus | State |
|---|---|---|
| M15 | Production infrastructure, recovery, outbox and worker leases | Complete |
| M16 | Federated identity, scoped secrets and trust boundaries | Complete |
| M17 | Secure remote-agent interoperability and authority attenuation | Complete |
| M18 | Reliability correlation, SLOs and continuous evaluation gates | Complete |
| M19 | Enterprise production acceptance and GA certification contract | Complete |
| M20 | Risk, runtime control hooks, registry, attestation, cryptographic metadata and compliance traceability | Complete |
| M21 | Production dependency readiness and evidence boundary | Complete |
| M22 | Token security, key lifecycle and attestation revocation | Complete |
| M23 | Registry lifecycle, compatibility and provenance governance | Complete |
| M24 | Adversarial agent security regression and release gate | Complete |
| M25 | Distributed reliability, RTO/RPO and disaster-recovery drills | Complete |
| M26 | Performance, capacity and economic governance | Complete |
| M27 | Enterprise SRE and compliance evidence | Complete |
| M28 | Supply-chain, release provenance and rollback assurance | Complete |
| M29 | Independent enterprise assurance and final certification gate | Complete |

M20-M29 add provider-neutral controls and certification surfaces. They do not move application/domain concerns into the Platform or provision external infrastructure from the core repository.

Production acceptance still requires operator verification of external infrastructure and evidence; repository CI does not prove that an external production environment is deployed.

See [docs/ROADMAP.md](docs/ROADMAP.md), [docs/ENTERPRISE-CONFORMANCE.md](docs/ENTERPRISE-CONFORMANCE.md), [docs/ENTERPRISE-BASELINE.md](docs/ENTERPRISE-BASELINE.md), and the M20-M29 phase specifications.

## Architectural boundary

The platform remains independent from FAS/FAS-Bench, FDSE, TADS/ReconOS, ThreatFade, Hezqara, FusionOps and Tinlance Agentic OS. These systems consume platform contracts/SDK surfaces; they do not become platform dependencies.

## Finalization

M29 is the final finite engineering-assurance phase. The Platform now enters continuous enterprise assurance: new threats, standards, incidents and production findings become new evidence/tests rather than arbitrary new roadmap phases.
