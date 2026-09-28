# Enterprise Conformance

The platform's enterprise claim is based on executable controls rather than milestone labels alone.

## Canonical sequence

Identity -> Authorization -> Approval -> Runtime -> Model Gateway -> Tool/MCP Gateway -> Sandbox -> Orchestration -> Memory -> Evidence/Event -> Observability -> Evaluation -> Domain SDK -> Enterprise

`GovernedExecutionService` provides the reference end-to-end path through the authority and evidence chain.

## Invariants

- Tenant identity is bound at request, task, run, model and tool boundaries.
- Authorization is evaluated outside model reasoning.
- High-risk or irreversible actions remain approval-gated.
- Tool and MCP calls are completely mediated against capability, action and resource.
- Model providers can be tenant/agent allowlisted and cannot exceed requested output budgets.
- Context excludes untrusted content by default and redacts secret-like material.
- Evidence is bounded, tenant-scoped and independently hash-verifiable.
- Trajectory is append-only in the reference store and hash-chain verifiable.
- Events are immutable, tenant-scoped and reject sensitive fields.
- Runtime state transitions and turn/tool budgets are enforced before consequential side effects.
- Evaluation does not grant authority.
- Domain SDKs remain consumers; domain products do not become platform dependencies.

## Production boundary

The repository provides a governed, provider-neutral core and reference adapters. Customer production deployment still requires real durable stores, secret management, approved model/tool providers, isolated execution infrastructure, telemetry backends, backup/restore, incident response, key management and operational SLOs.
