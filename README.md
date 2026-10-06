# Tinlance Agent Platform

> A governed execution substrate for secure autonomous AI systems that need identity, policy, approvals, isolation, evidence, and auditability at the execution boundary.

[![CI](https://github.com/LloydCoder/tinlance-agent-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/LloydCoder/tinlance-agent-platform/actions/workflows/ci.yml)
[![CodeQL](https://github.com/LloydCoder/tinlance-agent-platform/actions/workflows/codeql.yml/badge.svg)](https://github.com/LloydCoder/tinlance-agent-platform/actions/workflows/codeql.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python 3.12–3.14](https://img.shields.io/badge/python-3.12--3.14-blue.svg)](pyproject.toml)

> [!NOTE]
> The repository is the authoritative implementation of the Platform boundary. Repository CI proves repository controls and executable tests; it does not claim that external production infrastructure has been deployed.

## Visual architecture

~~~mermaid
flowchart LR
    D[Tinlance Agent Developer] --> OS[Tinlance Agent OS]
    OS --> SDK[Tinlance Agent Platform SDK]
    SDK --> P[Tinlance Agent Platform]
    P --> ID[Identity + Tenancy / JWT-JWKS verification]
    P --> AUTH[Authorization + Policy]
    P --> APP[Approval]
    P --> RUN[Governed Runtime]
    RUN --> J[Durable execution journal]
    P --> TOOL[Model / Tool / MCP Mediation]
    P --> SB[Sandbox + Secrets]
    P --> EV[Evidence + Audit]
    J --> EV
    C[Ecosystem Conformance] -. verifies .-> D
    C -. verifies .-> OS
    C -. verifies .-> SDK
    C -. verifies .-> P
    DOMAIN[Domain systems] --> SDK
~~~

## Why the Platform exists

Agent frameworks can produce an action; a governed execution substrate determines whether that action is allowed to happen.

| Concern | Tinlance Agent Platform |
|---|---|
| Identity | Normalized principals, agent identity, version binding, tenant binding |
| Authorization | Deny-by-default capabilities and complete mediation |
| Human control | Exact, expiring, resource-bound approvals |
| Runtime | Fail-closed lifecycle, durable state, budgets, cancellation, retry and terminal-state integrity |
| Models and tools | Provider-neutral mediation with policy and risk controls |
| MCP / remote agents | Scoped registration, protocol boundaries and authority attenuation |
| Sandbox | Isolated execution with command, path, network and resource controls |
| Secrets | Execution-scoped handles rather than ordinary model context |
| Evidence | Attributable, integrity-protected execution evidence and audit records |
| Enterprise assurance | Conformance, adversarial, reliability, supply-chain and release gates |

## Quick Start

Prerequisites: Python 3.12, 3.13, or 3.14.

~~~bash
git clone https://github.com/LloydCoder/tinlance-agent-platform.git
cd tinlance-agent-platform
python -m pip install -e ".[test,security]"
python apps/cli/tinlance_agent_platform_cli.py health
pytest -q
~~~

Expected CLI output is:

~~~text
ok
~~~

The five commands above install the repository, exercise the CLI health path, and run the test suite.

## Installation

### Development installation

~~~bash
python -m pip install -e ".[test,security]"
~~~

The test extra provides pytest, coverage, Ruff and mypy. The security extra provides pip-audit and CycloneDX SBOM tooling.

### Build installation

The project uses Hatchling through the standard Python build interface.

~~~bash
python -m pip install build
python -m build
~~~

### Requirements

| Requirement | Supported |
|---|---|
| Python | 3.12–3.14 |
| OS | Linux, macOS, Windows for the Python package; CI is Linux |
| Database tests | PostgreSQL 17.x in CI |
| Package build | Hatchling |

## Usage

### CLI health check

~~~bash
python apps/cli/tinlance_agent_platform_cli.py health
~~~

### CLI version surface

~~~bash
python apps/cli/tinlance_agent_platform_cli.py version
~~~

### Run the complete quality suite

~~~bash
python -m pip install -e ".[test,security]"
python -m pip check
ruff check .
ruff format --check .
mypy packages
pytest --cov=packages --cov-report=term-missing --cov-fail-under=85
~~~

### Database isolation checks

When changing migrations or tenancy behavior, run the PostgreSQL migration and isolation suite used by CI. See the SQL job in .github/workflows/ci.yml and the tests under database/tests/.

## Configuration

The core package has no runtime environment-variable contract in pyproject.toml and deliberately keeps provider-specific infrastructure outside the core repository.

| Area | Default / contract | Source |
|---|---|---|
| Python | 3.12–3.14 | pyproject.toml |
| Package version | 1.1.0 | pyproject.toml |
| Test command | pytest via tests/ | pyproject.toml |
| Lint | Ruff E, F, I, B, UP, SIM | pyproject.toml |
| Type checking | mypy strict | pyproject.toml |
| Coverage gate | 85% on packages | CI |
| Production persistence | External durable PostgreSQL | deployment/README.md |
| Production secrets | External secret manager | deployment/README.md |
| Production sandbox | External isolated runtime | deployment/README.md |

> [!WARNING]
> Do not put production credentials, customer data, private keys, or provider secrets into source files, model context, evidence records, or ordinary telemetry.

## Features

| Capability | Purpose |
|---|---|
| Identity and tenancy | Keep principals and executions bound to the correct tenant |
| Authorization and policy | Prevent capability possession from bypassing policy |
| Approvals | Require explicit, scoped human authorization for consequential actions |
| Governed execution | Re-authorize and validate controls immediately before side effects |
| Model gateway | Keep model providers behind a stable boundary |
| Tool and MCP gateway | Register and mediate tool resources without granting authority |
| Sandbox | Enforce filesystem, command, network and resource boundaries |
| Memory and context | Apply tenant scope, trust classification and redaction |
| Evidence and events | Preserve provenance, integrity and audit causality |
| Observability | Correlate traces, metrics and security-relevant events |
| Evaluation | Gate releases without granting runtime authority |
| Reference agents | Demonstrate the stable consumer boundary without becoming Platform authority |
| Enterprise assurance | Track reliability, adversarial security, supply chain and release evidence |

## Architecture and boundaries

The Platform is intentionally below Tinlance Agentic OS and domain products.

It remains independent from FAS/FAS-Bench, FDSE, TADS/ReconOS, ThreatFade, Hezqara, FusionOps and Tinlance Agentic OS. Those systems consume Platform contracts and SDK surfaces; they do not become Platform dependencies.

The canonical architectural precedence is:

1. Current implementation and executable tests
2. docs/ROADMAP.md for milestone vocabulary
3. ARCHITECTURE.md for stable system boundary and invariants
4. Enterprise baseline and conformance documents for production acceptance
5. Historical status files and ADRs for traceability

## Documentation

- [Documentation index](docs/README.md)
- [Ecosystem conformance](docs/integration/CONFORMANCE.md)
- [Architecture](ARCHITECTURE.md)
- [Canonical roadmap](docs/ROADMAP.md)
- [Enterprise baseline](docs/ENTERPRISE-BASELINE.md)
- [Enterprise conformance](docs/ENTERPRISE-CONFORMANCE.md)
- [R10 governed execution](docs/R10-GOVERNED-EXECUTION.md)
- [Release readiness](docs/RELEASE-READINESS.md)
- [Release security](docs/RELEASE-SECURITY.md)
- [Security threat models](security/README.md)
- [Changelog](CHANGELOG.md)
- [LLM-oriented index](llms.txt)

## Contributing

Security-sensitive contributions must preserve the platform boundary and add regression or adversarial coverage for new security invariants. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## License and acknowledgements

Tinlance Agent Platform is licensed under the [Apache License 2.0](LICENSE).

Copyright 2024–2026 Tinlance Limited.

The project uses GitHub Actions, CodeQL, Dependabot, pip-audit, CycloneDX and Sigstore in its repository security and release workflow.

<details>
<summary>Roadmap</summary>

M0–M14 form the canonical Agent Platform roadmap. M15–M29 are the completed post-M14 enterprise assurance sequence. M29 is the final finite engineering-assurance phase; the project then moves to continuous enterprise assurance.

See [docs/ROADMAP.md](docs/ROADMAP.md).

</details>

<details>
<summary>Support</summary>

Use [SUPPORT.md](SUPPORT.md) for usage questions and enterprise contact information. Report suspected vulnerabilities privately through [SECURITY.md](SECURITY.md).

</details>

<details>
<summary>Production boundary</summary>

Production deployments require external evidence for durable persistence, secret management, isolated execution, telemetry, backups, incident response and operational ownership. Repository CI does not manufacture that evidence.

See [deployment/README.md](deployment/README.md) and [docs/ENTERPRISE-BASELINE.md](docs/ENTERPRISE-BASELINE.md).

</details>

## Production runtime sequence

M13.1 establishes durable execution state and fail-closed recovery. M13.2 adds cryptographic JWT/JWKS identity verification while keeping authorization authoritative and separate. See the production-runtime documentation for the acceptance gates.

M13.3 closes the authorization seam: a verified identity is insufficient without capability authorization, policy allowance, and any required approval bound to the exact execution intent.
