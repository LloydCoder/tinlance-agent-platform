# Tinlance Agent Ecosystem Integration

Tinlance Agent Platform is the authoritative execution and authority plane beneath the other three agent repositories.

TSIC is the canonical ecosystem integration, contract, compatibility, conformance, and certification authority.

## Authority boundaries

- TSIC owns ecosystem integration contracts, compatibility policy, conformance requirements, and certification evidence.
- Agent Platform is the sole authority for identity, tenancy, authorization, policy, approvals, budgets, sandbox/tool/MCP execution, secrets, runtime, evidence, audit, and observability.
- Agent OS owns workspace, environment, lifecycle, orchestration, UX, builder, and fleet concerns.
- Platform SDK is a typed developer/client surface and never authorizes or grants execution authority.
- TADL declares and validates developer intent and artifacts; it is a conformance consumer, not an ecosystem integration authority.

TSIC does not enter the runtime authority path. The Platform does not depend on TADL, Agent OS, or the SDK for authority.

## TSIC cross-repository contract

The Agent Platform CI gate consumes the immutable TSIC reference adapter at revision b970805933ba80902417105389362222b3196208. The gate validates the canonical repository mapping, governance role, contract binding set, and authority invariants.

Run locally:

    python scripts/tsic_conformance.py

The check is fail-closed. It reads only machine-readable TSIC contract surfaces at an immutable Git revision; it does not copy TSIC authority into the Platform repository.

Canonical wire contract: API version 1.1, POST /v1/agent-platform, with governed-execution.v1 for consequential tool mediation.

The integration boundary binds tenant and subject to the authenticated principal, re-checks authorization at the consequential side-effect boundary, enforces idempotency for guarded operations, and emits authoritative evidence/events.

## Conformance

The Agent Platform repository performs a direct, pinned TSIC contract-consumption check in CI. The TADL-hosted four-repository suite remains a local agent-system compatibility gate; TSIC remains the canonical ecosystem certification authority.

Passing the TSIC check proves compatibility with the pinned TSIC contract surfaces. It does not claim that external production infrastructure is deployed.

## Production boundary

The reference HTTP server is a contract test boundary. Production deployments must add the hardened TLS, token verification, durable persistence, secrets, isolated runtime, telemetry, and operational controls described by the production documentation.
