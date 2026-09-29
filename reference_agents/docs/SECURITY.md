# Reference Agent Security Model

The suite follows the Platform invariants and does not introduce a parallel security authority.

## Threats covered

- direct and indirect prompt injection;
- malicious repository/source content;
- malicious tool output;
- secret exfiltration;
- tenant confusion;
- privilege escalation;
- approval bypass;
- replay/duplicate consequential requests;
- excessive tool-call planning;
- unbounded workflows;
- context poisoning.

## Controls

1. Agent identity is selected by Platform-scoped UUIDs; the SDK sends them as request assertions.
2. Consequential calls use the SDK's request-ID/idempotency contract.
3. Consequential workflows stop at explicit approval boundaries.
4. Tool descriptors are inert metadata.
5. Findings require evidence references.
6. Untrusted content is retained as data rather than interpreted as authority.
7. No agent-local secret or sandbox subsystem exists.
8. No automatic retry is implemented for consequential actions.
9. R10 execution fields are derived from immutable ToolPlan metadata; callers cannot downgrade risk, timeout, sandbox, evidence, or classification through the agent helper.
10. Approval requests bind the exact execution intent used by `tools.execute`.
11. Pending execution resumption reuses the same idempotency key and execution identity; completed or ambiguous outcomes are not silently replayed.
12. MCP discovery and tool annotations are treated as untrusted metadata; the Platform remains the enforcement point.


## Current standards alignment

The suite follows the current security posture reflected in NIST's 2026 software/AI-agent identity and authorization work and final IR 8587 guidance on token/assertion protection and lifecycle controls. It also follows OWASP's 2026 agentic risk model, particularly agent goal hijacking, tool misuse, identity/privilege abuse, agentic supply-chain risks, human-agent trust exploitation, and rogue-agent controls. Where MCP is used, its authorization and untrusted-tool metadata model is treated as an integration boundary rather than a source of authority.

The agent package does not implement DPoP itself. Deployments using OAuth bearer tokens should apply sender-constrained access-token protections where appropriate; RFC 9449 is a deployment-level control, not an agent-local authorization primitive.
