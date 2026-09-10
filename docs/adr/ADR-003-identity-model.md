# ADR-003 — Identity model

**Status:** Accepted

Agents are first-class security principals. Authentication adapters produce provider-neutral principals and immutable request context. Tenant, environment, subject, roles and scopes are explicit authorization inputs.

**Decision:** identity provider claims never become the platform domain model; agent version and owner are attributable execution metadata.
