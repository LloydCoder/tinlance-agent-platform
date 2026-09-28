# Tinlance Agent Platform

Tinlance's generic governed AI-agent execution substrate.

M1 adds a durable tenant-scoped domain and a governed execution boundary.

## Core invariant
Capability != authority. Models never acquire authority by generating output.

## M1 domain
Tenant -> Customer -> Project -> Repository -> Assessment -> Finding/Evidence.

The domain enforces ancestry, lifecycle and idempotency. PostgreSQL enforces relational ancestry and RLS.

## Execution contract
Contract v1 carries tenant/actor identity, action, risk, data classification, approval reference and resource limits. The Docker adapter denies execution when the runtime is unavailable and defaults to network isolation.

## Repository boundary
Agent Platform remains separate from Agentic OS, FDSE, TADS, ThreatFade, Hezqara and other products. They consume platform contracts.

## Technology posture
Python 3.12-3.14; PostgreSQL; provider-neutral contracts; modular monolith; no premature distributed infrastructure.