# Documentation

This directory contains the operational and engineering documentation for Tinlance Agent Platform.

## Start here

| Need | Document |
|---|---|
| Understand the product | [README](../README.md) |
| Understand the stable architecture | [Architecture](ARCHITECTURE.md) |
| Learn the canonical milestone sequence | [Roadmap](ROADMAP.md) |
| Assess production readiness | [Enterprise baseline](ENTERPRISE-BASELINE.md) |
| Check repository conformance | [Enterprise conformance](ENTERPRISE-CONFORMANCE.md) |
| Prepare a release | [Release readiness](RELEASE-READINESS.md) |
| Verify release security | [Release security](RELEASE-SECURITY.md) |
| Understand governed execution | [R10 governed execution](R10-GOVERNED-EXECUTION.md) |
| Review production-runtime hardening | [Production runtime index](production-runtime/README.md) |

## Documentation model

The documentation follows a practical Diátaxis-inspired structure:

- Tutorials: end-to-end runnable examples live in repository tests and reference-agent examples.
- How-to: deployment, release, security, and operational documents explain task-oriented procedures.
- Explanation: architecture, ADRs, threat models, milestone specifications, and enterprise conformance explain why the system is designed this way.
- Reference: contracts, package APIs, schemas, and executable tests define exact behavior.

Milestone status files are historical traceability records. When they conflict with current implementation or canonical architecture, follow the precedence defined in [ROADMAP.md](ROADMAP.md).

## Trust and production boundary

The Platform deliberately keeps provider-specific infrastructure outside the core repository. Production deployment requires external evidence for persistence, secret management, sandboxing, telemetry, backups, incident response, and operational ownership.
