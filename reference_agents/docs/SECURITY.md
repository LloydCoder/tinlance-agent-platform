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

Current API 1.1 does not publish approval-decision or tool-execution operations, so the suite does not simulate those calls.
