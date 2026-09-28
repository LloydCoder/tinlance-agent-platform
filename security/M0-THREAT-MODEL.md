# M0 Platform Threat Model

## Assets

Tenant identity and authorization state; approval state; credentials and secret handles; tool/model provider bindings; execution workspaces; evidence, events and trajectories; budgets; audit/telemetry metadata.

## Trust boundaries

1. Human or upstream application -> platform request context.
2. Model -> governed harness.
3. Retrieved/external content -> context builder.
4. Tool/MCP provider -> platform gateway.
5. Sandbox workload -> host and platform control plane.
6. Domain consumer -> platform SDK.
7. Application -> durable database and secret manager.

## Primary threats

- Cross-tenant access or confused-deputy behavior.
- Prompt injection causing unauthorized side effects.
- Capability or approval spoofing/bypass.
- Tool/MCP output being promoted to authority.
- Credential or secret leakage into context, logs or evidence.
- Sandbox escape or resource exhaustion.
- Evidence deletion, mutation or false attribution.
- Evaluation output being treated as authorization.
- Supply-chain compromise of dependencies or build artifacts.

## Required invariants

Authority is established outside model reasoning; consequential actions are re-authorized at the execution boundary; prohibited capabilities remain impossible; tenant identity is immutable; untrusted content remains data; evidence is attributable and integrity-verifiable; failures deny by default.
