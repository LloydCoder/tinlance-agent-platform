# Tinlance Agent Platform Architecture

Agent Platform is the generic governed execution substrate. It is separate from Tinlance Agentic OS and all domain products. FDSE, TADS, ReconOS, ThreatFade, Hezqara and FusionOps consume stable contracts/SDK surfaces; Agent Platform never imports them.

## Planes

Control plane: identity, tenancy, authorization, policy, approvals, budgets, registries and domain registration.

Execution plane: runtime, orchestration, model gateway, tool/MCP gateway, secrets and sandbox adapters.

Evidence plane: events, evidence, trajectory, audit, observability and evaluation.

## Authority chain

identity -> tenancy -> authorization -> policy -> approval -> execution boundary -> evidence

Model output, external content, tool output and peer-agent messages are untrusted. No provider adapter can grant authority. A tool registration describes capability; it does not authorize a principal.

## Dependency DAG

contracts -> kernel -> services -> adapters -> apps

The direction is executable in tests/architecture/test_boundaries.py. Core packages may not import provider SDKs, web frameworks, database clients or domain repositories. SDK is an outward-facing composition surface, not a kernel dependency.

## Enterprise persistence

PostgreSQL is the reference durable control-plane boundary. Tenant RLS is defense in depth, not a replacement for application authorization. Cross-tenant composite foreign keys prevent an otherwise authorized row from referencing another tenant's parent resource.

Evidence, trajectory and audit records are append-only surfaces. Event/outbox publication remains a transactionally durable adapter responsibility.

## Agentic OS relationship

Agent Platform is not the operating environment itself. Agentic OS is a higher-level layer that composes humans, agents, organizations, workflows, applications and domain products using this governed substrate.

## World intelligence boundary

TADS/ReconOS/world-intelligence data can be represented as evidence or domain context, but intelligence never becomes authority automatically. Domain registration cannot alter kernel authorization rules. See ADR-013 and ADR-014.

## Production boundary

Reference in-memory implementations are deterministic and testable. Production adapters must provide durable storage, secret management, telemetry, sandbox supervision, backups and recovery without moving those responsibilities into contracts or kernel code.
