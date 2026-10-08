# Tinlance Agent Ecosystem Conformance

Agent Platform is the authoritative target of the cross-repository conformance gate, while TSIC is the canonical ecosystem certification authority.

## Platform obligations

The conformance gate verifies that the Platform:

- exposes API 1.1 at POST /v1/agent-platform;
- binds requests to the authenticated tenant and subject;
- fails closed on API-version or principal mismatch;
- enforces idempotency for guarded consequential operations;
- preserves trace and request metadata at the boundary; and
- remains the sole consequential authority plane.

## TSIC obligations

The Platform CI gate consumes immutable TSIC reference adapter revision b970805933ba80902417105389362222b3196208 and verifies:

- canonical Agent Platform repository mapping;
- execution-authority governance role;
- TSIC contract registry membership;
- identity, registration, event, delivery, trace, interoperability, and economic contract bindings;
- adapter authority invariants.

The check is fail-closed and uses an immutable Git revision.

## Authority invariant

TADL declarations, Agent OS intent, SDK requests, model output, memory, retrieved content, tool output, and external responses never grant authority. The Platform decides whether a consequential operation may occur and produces authoritative evidence.

## Production boundary

Passing the TSIC conformance check does not claim that production PostgreSQL, external secret management, hardened TLS/token verification, sandbox infrastructure, enterprise identity, telemetry, backups, or incident response are deployed.
