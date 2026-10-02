# M17 — Agent Interoperability

M17 establishes a secure interoperability contract for remote agents. Discovery metadata and protocol negotiation are descriptive; they never grant Platform authority.

The contract requires secure endpoints, normalized capability metadata, credential-free agent cards, and authority-attenuating remote delegation. Every consequential remote action must re-enter the Platform identity, authorization, policy, approval and R10 execution boundary.

The design is aligned with the current A2A specification, which defines Agent Cards, authenticated transport, server-side authorization, least privilege, and caller-scoped access. A2A's current released specification is 1.0.0; integrations must pin and test the protocol version they support rather than assuming a floating standard.

MCP remains an untrusted integration boundary and is not an authority source.
