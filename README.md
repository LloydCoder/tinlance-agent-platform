# Tinlance Agent Platform

Tinlance's generic governed AI-agent execution substrate.

## Core invariant

> capability != authority

Models do not receive authority merely by producing output. Consequential execution is mediated by explicit identity, tenancy, authorization, deterministic policy, risk, approval, isolation, budgets, evidence and audit controls.

## Architecture

```
CONTROL PLANE
identity -> tenancy -> authorization -> policy -> approvals -> registries

EXECUTION PLANE
runtime -> orchestration -> model/tool gateways -> sandbox -> adapters

EVIDENCE PLANE
events -> trajectory -> provenance -> audit -> observability -> evaluation
```

## M0 foundation

The current milestone establishes the clean-room kernel/control boundaries:

- contracts
- kernel
- identity
- tenancy
- authorization
- policy

The former `packages/common` dumping ground is removed.

## Repository boundary

Agent Platform is separate from the higher-level Tinlance Agentic OS and from FDSE, TADS, ThreatFade, Hezqara, ReconOS, FadeReach and other products. Those systems consume platform contracts; the platform does not import them.

## Technology posture

- Python 3.12–3.14
- framework-free kernel
- PostgreSQL with application authorization plus database RLS
- transactional outbox before a distributed broker
- provider-neutral model/tool ports
- OpenTelemetry-compatible observability boundary
- risk-tiered sandbox selection
- modular monolith before premature microservices

M0 is foundation-complete, not production-ready. Future capabilities require their own implementation, tests, threat model and operational validation.
