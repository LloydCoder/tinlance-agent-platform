# ADR-001 — Agent Platform boundaries

**Status:** Accepted

The platform owns generic identity, authority, execution, policy, model/tool mediation, evidence and control primitives. Domain repositories own domain behavior. The platform is a consumer-facing substrate, not an FDSE/TADS/ThreatFade application.

**Decision:** domain code registers against stable contracts; core layers never import domain logic.
