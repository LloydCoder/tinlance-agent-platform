# ADR-001 — Agent Platform boundaries

**Status:** Accepted

The platform owns generic identity, authority, execution, policy, model/tool mediation, evidence and control primitives. Domain repositories own domain behavior. The platform is a consumer-facing substrate, not an FDSE/TADS/ThreatFade application.

**Decision:** domain code registers against stable contracts; core layers never import domain logic.


## MCP/A2A interoperability boundary (P9)

The MCP protocol adapter lives in the MCP boundary package and depends only on the permitted contracts, kernel and policy primitives. The HTTP transport may mount the injected adapter at `POST /mcp`, but every tool call is converted into a Platform dispatch request and remains subject to the Platform's existing authority checks. The MCP package must not import the API package or duplicate authentication, authorization, approval, budget, sandbox or execution policy. A2A discovery cards and remote delegation are untrusted metadata; remote requests must validate the trusted issuer, tenant, audience, destination addresses and transport behavior before dispatch. SDK and Agent OS surfaces remain authority-free.
