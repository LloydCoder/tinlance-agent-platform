# M0 Threat Model

## Assets

- agent identities and credentials
- tenant data and memory
- model inputs/outputs
- tool capabilities
- policy definitions and decisions
- task state and workflow history
- evidence and audit records
- sandbox state and artifacts
- operator approval authority

## Trust boundaries

1. Human/operator -> control plane
2. Control plane -> execution worker
3. Model provider -> platform
4. Agent/model -> tool gateway
5. External content -> agent context
6. Worker -> durable storage
7. Tenant -> tenant
8. Domain plugin -> platform kernel

## Threat actors

- malicious user
- compromised user identity
- malicious or compromised agent
- malicious model/provider
- malicious tool or MCP server
- malicious web content
- compromised worker
- supply-chain attacker
- insider
- external network attacker

## Primary abuse cases

| Threat | Required control |
|---|---|
| Cross-tenant access | immutable tenant context + authorization + database RLS |
| Privilege escalation | capabilities separated from credentials and authorization |
| Tool abuse | registered tool gateway + policy + risk + approval |
| Prompt injection | external content treated as untrusted data |
| Credential theft | secret broker/injection outside model context |
| Worker compromise | execution-plane isolation from control plane |
| Replay/duplicate side effect | idempotency keys + durable execution state |
| Policy bypass | fail-closed enforcement outside model reasoning |
| Agent loop | depth, step, time, concurrency and budget limits |
| Evidence tampering | append-only records + cryptographic integrity where required |
| Supply-chain compromise | pinned dependencies, SBOM, scanning, signed artifacts |
| Model substitution | immutable model version registry and policy |
| Approval bypass | approval state verified at execution boundary |
| Data exfiltration | data classification + network policy + tool scopes |
| Sandbox escape | risk-tiered isolation and independent kill controls |

## Security invariants

1. Model output never grants authority.
2. Tool output never changes policy.
3. External content never changes identity or capabilities.
4. Every external side effect has an attributable principal.
5. Prohibited actions cannot be approved into execution.
6. Emergency controls operate independently of the agent.
7. Tenant context cannot be widened by a child agent.
8. Secrets never enter normal trajectory or model-context payloads.

## M0 validation strategy

Security tests begin with deterministic contract tests. Adversarial scenario suites will be expanded in M2, M4, M7 and M10. No production-readiness claim is made by this threat model alone.
