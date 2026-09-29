# R10 Agent Certification

**Contract authority:** `governed-execution.v1`  
**Certification suite:** `tests/certification/test_r10_boundary.py`  
**Release gate:** the certification workflow must pass for every agent/platform change that can reach consequential execution.

## Purpose

This suite is the permanent adversarial boundary test for Tinlance agents. It does not certify an agent by trusting its planner, prompt, tool description, or local executor. It certifies that the Agent Platform remains the only authority capable of authorizing and executing consequential actions.

The suite is intentionally attack-oriented and treats agent proposals, tool metadata, MCP responses, external outputs, and client assertions as untrusted.

## Required attack classes

| Class | Required invariant |
| --- | --- |
| Tenant escape | No principal, agent, run, tool, evidence, approval, budget, or status can cross tenant scope. |
| Forged capability | Capability identity and version must match the registered Platform contract. |
| Capability/version confusion | Capability version and tool version are independently bound at the execution boundary. |
| Approval substitution | Approval is bound to tenant, run, action, resource, and execution intent. |
| Approval replay | Consumed approvals cannot authorize a second execution. |
| Self approval | A requester cannot approve its own consequential request; an authenticated approver identity is mandatory. |
| Idempotency race | Concurrent deliveries of one tenant/key/fingerprint produce one consequential execution. |
| Budget race | Concurrent reservations cannot oversubscribe the authoritative budget. |
| Timeout | A hard adapter timeout is terminal and is never silently converted to success. |
| Ambiguous outcome | An execution whose outcome cannot be established becomes `outcome_unknown` and is non-retryable. |
| Crash/recovery | Durable idempotency survives repository recreation and preserves execution identity/result. |
| Secret leakage | Secret output is redacted before result/evidence exposure; event stores reject sensitive fields. |
| Malicious metadata | Tool descriptions and client-supplied metadata cannot grant authority or raise risk ceilings. |
| Hostile MCP | MCP is treated as an untrusted integration boundary; external output cannot mutate Platform authority. |
| Evidence/audit causality | Evidence and lifecycle events carry the same immutable execution identity and tenant/run partition. |
| Contract substitution | Unsupported R10 contract versions are rejected. |

## Certification rule

A future agent is eligible for Tinlance Platform certification only when:

1. it uses the R10 SDK/Platform execution boundary for consequential actions;
2. it cannot directly invoke an authoritative executor;
3. it passes the reference-agent integration tests applicable to its declared capabilities;
4. the full adversarial certification suite is green;
5. its declared capabilities, tool versions, approval requirements, evidence requirements, and sandbox requirements are compatible with R10;
6. no test is weakened, skipped, or reclassified merely to make an agent pass.

Passing this suite certifies the **boundary behavior of the Platform and the agent integration under test**. It does not certify external infrastructure, identity providers, sandbox implementations, secret managers, MCP servers, or third-party systems that are outside the supplied test doubles.

## External alignment

The suite follows the same security direction as NIST's 2026 software-agent identity/authorization work and NIST IR 8587's guidance on token/assertion protection and lifecycle controls. OWASP's 2026 agentic guidance explicitly recommends structured adversarial validation for tool misuse, privilege escalation, data exfiltration, approval bypass, multi-agent chaining, and runaway resource use.

MCP's 2026-07-28 specification likewise treats tool behavior and annotations as untrusted unless obtained from a trusted server and requires authorization controls around external servers. Tinlance therefore keeps MCP behind the Platform boundary rather than allowing MCP to become an authority source.

## CI policy

The certification workflow runs on pull requests and pushes. It must remain independently visible from the general CI suite so a regression in the authority boundary cannot be hidden inside a broad green build.

The suite is additive to normal unit, integration, CodeQL, secret scanning, and reference-agent workflows.
