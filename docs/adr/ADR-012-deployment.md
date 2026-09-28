# ADR-012 — Deployment

**Status:** Accepted

Development, staging and production are separate environments. The platform remains cloud-neutral and starts as a modular deployment. Infrastructure becomes independently scalable only when load, fault isolation or security requirements justify it.

**Decision:** AWS is supported but never embedded into core contracts.
