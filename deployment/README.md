# Production Deployment Contract

Production deployments must provide external secret resolution, durable PostgreSQL persistence, transactional outbox delivery, isolated sandbox execution, telemetry, backups, restore verification, health/readiness checks, incident-response controls, operational ownership and immutable release artifacts.

The Platform records readiness evidence but does not provision provider-specific infrastructure in the core repository. Runtime code must not contain deployment credentials.

The M21 readiness contract requires evidence for every dependency category before a production release can be declared ready:

- database
- outbox
- secret manager
- sandbox
- telemetry
- backup
- incident response
- ownership

Repository CI verifies the readiness contract itself; it does not manufacture external evidence.
