# M21 — Production Infrastructure

## Objective

Turn the M19 production boundary into an explicit, evidence-backed readiness contract without introducing provider-specific infrastructure into the Platform core.

## Readiness dependencies

M21 tracks eight external dependency categories:

1. durable database;
2. transactional outbox/queue delivery;
3. external secret manager;
4. isolated sandbox/runtime;
5. telemetry backend;
6. backup and restore capability;
7. incident-response controls;
8. operational/security ownership.

A verified dependency must have an evidence reference. Missing or unverified dependencies block production readiness.

## Boundary

The readiness contract is a certification surface, not a provisioning engine. PostgreSQL, KMS, secret managers, queues, telemetry systems, sandbox supervisors and cloud infrastructure remain deployment-specific adapters.

## Completion evidence

M21 is complete only when the readiness contract, tests, deployment documentation, architecture/conformance documentation and every CI/security workflow are green.
