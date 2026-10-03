# Tinlance Agent Platform

Tinlance Agent Platform is the governed execution substrate beneath Tinlance Agentic OS. It owns identity, tenancy, authorization, policy, approval, runtime, model/tool/MCP mediation, sandbox, secrets, budgets, evidence, audit and governed execution. Domain products consume stable contracts and SDK surfaces; they do not become platform dependencies.

## Enterprise evolution

The canonical M0-M14 roadmap is complete. The serial post-M14 enterprise track is now:

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
| M24 | Adversarial agent security regression and release gate | In progress |

M20-M24 add provider-neutral controls and certification surfaces. They do not move application/domain concerns into the Platform or provision external infrastructure from the core repository.

Production acceptance still requires operator verification of external infrastructure and evidence; repository CI does not prove that an external production environment is deployed.

See [docs/ROADMAP.md](docs/ROADMAP.md), [docs/ENTERPRISE-CONFORMANCE.md](docs/ENTERPRISE-CONFORMANCE.md), [docs/ENTERPRISE-BASELINE.md](docs/ENTERPRISE-BASELINE.md), [docs/M20-CONTROL-EXPANSION.md](docs/M20-CONTROL-EXPANSION.md), [docs/M21-PRODUCTION-INFRASTRUCTURE.md](docs/M21-PRODUCTION-INFRASTRUCTURE.md), [docs/M22-IDENTITY-CRYPTO-ATTESTATION.md](docs/M22-IDENTITY-CRYPTO-ATTESTATION.md), [docs/M23-REGISTRY-GOVERNANCE.md](docs/M23-REGISTRY-GOVERNANCE.md), and [docs/M24-ADVERSARIAL-AGENT-SECURITY.md](docs/M24-ADVERSARIAL-AGENT-SECURITY.md).

## Architectural boundary

The platform remains independent from FAS/FAS-Bench, FDSE, TADS/ReconOS, ThreatFade, Hezqara, FusionOps and Tinlance Agentic OS. These systems consume platform contracts/SDK surfaces; they do not become platform dependencies.
