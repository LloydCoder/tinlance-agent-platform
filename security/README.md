# Security Threat Models

Threat models are maintained by boundary, not by historical milestone number. Each model identifies assets, trust boundaries, abuse cases, controls, and required executable tests.

- `M0-THREAT-MODEL.md` — platform-wide trust model and assets
- `M2-AUTHORIZATION-THREAT-MODEL.md` — identity, tenant and capability escalation
- `M4-RUNTIME-THREAT-MODEL.md` — lifecycle, budgets, replay and fail-open runtime paths
- `M7-SANDBOX-THREAT-MODEL.md` — isolation, filesystem, network and resource escape
- `M10-EVIDENCE-THREAT-MODEL.md` — evidence/event integrity, provenance and tamper resistance

A threat-model claim is not considered closed until the corresponding invariant has executable test coverage.
