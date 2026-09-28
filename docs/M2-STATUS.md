# M2 Status — Execution and Provider Boundaries

M2 introduces provider-neutral execution ports, an agent runner, execution-only secret handles, an event/outbox contract, and append-only evidence primitives.

## Security boundary

Models remain untrusted decision makers. Tool authorization, policy, approval and sandbox controls remain outside model-provider adapters. Secrets are represented by versioned handles and resolved only for execution. This follows least-privilege, complete-mediation and human-approval guidance for agent systems. citeturn0search0turn1search11

## Explicit non-claims

The in-memory stores are deterministic reference implementations, not durable production storage. PostgreSQL durability and transactional outbox delivery are M3. A production sandbox provider is M10.
