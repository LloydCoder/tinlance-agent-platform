# Tinlance Agent Platform Reference Agents

Reference implementations that exercise the **external Tinlance Agent Platform SDK** against the governed Tinlance Agent Platform.

These agents are intentionally domain-oriented. They do not implement identity, tenancy, authorization, policy, approvals, secrets, sandboxing, evidence authority, or tool execution.

## Reference agents

- **Security Research Agent** — security investigation planning, governed run creation, approval requests, and evidence-backed result collection.
- **Software Engineering Agent** — repository/code/CI workflow planning, governed run creation, approval boundaries for mutations, and result collection.
- **Intelligence Research Agent** — structured research, source/evidence interpretation, demand-signal/account-intelligence workflows, and governed report composition.

FAS, FDSE, and TADS remain independent domain systems. These reference agents consume their concepts and/or outputs; they do not import or replace them.

## Boundary

```
Reference Agent
     |
     | external SDK v0.1 / Platform API 1.1
     v
Tinlance Agent Platform
     |
     +-- identity / tenant binding
     +-- authorization / policy
     +-- approvals
     +-- tools / MCP
     +-- secrets / sandbox
     +-- evidence / events
     +-- execution
```

The local tool registry in this package is **metadata only**. A tool descriptor never grants authority and no reference agent contains a local unrestricted executor.

## Current Platform API boundary

The current API 1.1 contract exposes:

- health
- principal lookup
- tenant-scoped agent discovery
- capability discovery
- governed run creation/cancellation
- approval request creation
- run event references
- evidence references

It does **not** expose approval decisions, direct remote tool execution, evidence content retrieval, run waiting, or streaming. The reference agents therefore do not invent those operations. The complete external golden path is tested through the currently published contract, while the unavailable execution-after-approval segment is explicitly tracked as a Platform API capability gap rather than simulated.

## Evidence discipline

Agent outputs distinguish:

1. observation;
2. source/reference;
3. evidence reference;
4. domain analysis;
5. finding/hypothesis;
6. conclusion.

An LLM assertion or untrusted tool/source payload is never promoted to authoritative evidence by the agent.

## Security posture

The suite is designed around current OWASP agentic-security guidance and NIST work on agent identity/authorization:

- least privilege and complete mediation;
- explicit tenant binding;
- approval for consequential actions;
- untrusted-content isolation;
- no secret handling in agent context;
- bounded tool/request plans;
- replay-sensitive consequential calls;
- deterministic adversarial evaluation.

MCP integrations must remain behind the Platform gateway. The suite does not treat MCP discovery metadata as authority.

## Development

```bash
python -m pip install -e ".[test]"
pytest -q
ruff check .
ruff format --check .
mypy src tests
```

The CI job pins the SDK to the exact audited commit used by the compatibility matrix.

## Compatibility

| Reference Agents | External SDK | Platform API | Python |
|---|---|---|---|
| 0.1.x | 0.1.x | 1.1 | 3.12–3.14 |

A new remote operation requires a versioned Platform contract and corresponding SDK contract first.

## Repository placement

The reference suite currently lives under `reference_agents/` in the Platform repository to keep the proof suite close to the authoritative executable contracts without introducing a third release artifact prematurely. It is isolated as its own Python package and may be split into `LloydCoder/tinlance-reference-agents` once independent release cadence or ecosystem adoption justifies a repository boundary.

This placement does **not** make the agents Platform dependencies: the package imports the external SDK and never imports Platform implementation packages in production agent code.
