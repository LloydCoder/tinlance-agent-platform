# Tinlance Agent Platform

Private proprietary control substrate for governed AI-agent execution.

## Mission

Tinlance Agent Platform provides the generic security and execution primitives required to operate autonomous and human-supervised agents without giving models implicit authority.

The invariant is:

> capability != authority

All consequential execution is mediated by identity, authorization, policy, risk, approval, budgets, isolation, evidence, and audit controls.

## Status

**M0 — Foundation: IN PROGRESS**

The repository was intentionally empty at the start of M0. This first implementation establishes the architecture and kernel boundaries before introducing provider-specific or domain-specific execution.

No subsystem is called production-ready until implementation, tests, security controls, failure semantics, observability, documentation, and deployment validation exist.

## Architecture

```text
CONTROL PLANE
identity -> authorization -> policy -> approvals -> budgets -> registries
                         |
                         v
EXECUTION PLANE
orchestration -> agent runtime -> model/tool adapters -> isolated execution
                         |
                         v
EVIDENCE PLANE
events -> trajectory -> provenance -> audit -> evaluation -> observability
```

## Initial technology posture

- Python 3.12+ for the kernel and control-plane services.
- FastAPI only at the application/API boundary; core packages remain framework-neutral.
- PostgreSQL as the durable control-plane store and tenant isolation backstop.
- PostgreSQL outbox/events before introducing a distributed event broker.
- OpenTelemetry-compatible telemetry at the platform boundary.
- Provider-neutral model and tool ports.
- MCP and other protocols are adapters, never the internal security boundary.
- Sandbox technology is selected by workload risk rather than assumed to be containers-only.

## Repository boundary

This repository owns generic agent infrastructure. FDSE, TADS, ThreatFade, ReconOS, FadeReach, and other domain products remain consumers/adapters and must not duplicate the platform kernel.

## Security posture

The architecture is informed by current NIST agent identity/authorization work, OWASP Agent Control Standard, MCP authorization guidance, and current agent-runtime practices. These sources validate the need for runtime-enforced controls, but they do not replace Tinlance's own authorization and policy enforcement.

## Development rule

Use feature branch -> inspect -> design -> implement -> test -> security review -> CI -> review -> merge.

Never claim a capability is implemented from the existence of an interface or placeholder alone.
