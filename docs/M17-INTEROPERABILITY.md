# M17 — Agent Interoperability

M17 establishes a secure interoperability contract for remote agents. Discovery metadata and protocol negotiation are descriptive; they never grant Platform authority.

The Platform P9 implementation work targets:
- MCP `2026-07-28` stateless HTTP at `POST /mcp`, with per-request client metadata, protocol/method/name header agreement, Origin validation, bounded payloads, deterministic tool listing, argument-schema validation and idempotency enforcement.
- A2A `1.0.0` Agent Cards with canonical signed payloads, an injected trusted signature-verifier interface, explicit key ID/algorithm policy, and HTTPS-only outbound transport with public-address validation. The transport contract must pin validated addresses and must not follow redirects.
- Remote delegation with immutable capability attenuation, bounded TTL, issue/expiry timestamps, and required tenant, issuer and audience binding at validation time.
- Every consequential remote action re-enters the Platform identity, authorization, policy, approval, budget, sandbox and governed-execution boundary.

The MCP protocol package depends only on allowed Platform contracts/kernel/policy primitives. The HTTP transport mounts the injected MCP service without making MCP a second authorization authority. Agent OS composes protocol workflows; the SDK exposes descriptive typed contracts only; TADL validates artifacts; TSIC remains the system integration/certification authority.

P9 implementation PRs are not certification. The exact-head CI/security gates and final four-repository + TSIC integration baseline must pass before P9 is marked certified. Repository tests do not prove that production TLS, OAuth, network egress pinning, shared rate limiting, telemetry or deployed task persistence are configured.
