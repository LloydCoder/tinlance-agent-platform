# M19 — Enterprise Certification & Production GA

M19 is the final post-M14 engineering gate. It does not claim that external production infrastructure exists merely because the repository passes CI. Instead, it provides a typed acceptance contract requiring operator evidence for every production control.

## Repository gates

The release must have green:

- CI across Python 3.12, 3.13 and 3.14;
- PostgreSQL migration/RLS/integrity tests;
- R10 adversarial certification;
- Reference Agents certification;
- CodeQL;
- secret scanning;
- supply-chain/audit checks in the release workflow.

## Production acceptance

The operator must independently verify identity, authorization, durable persistence/recovery, external secrets and rotation, sandbox/resource isolation, telemetry/alerting, continuous evaluation, signed release provenance, backups/restore drills, interoperability, and operational/security ownership.

EnterpriseAcceptance deliberately requires an evidence reference for every verified control. A green repository CI run is evidence of repository behavior; it is not evidence that external production infrastructure has been deployed.

## GA rule

No production certification is valid if any required control is unverified, lacks evidence, or is supported only by a test double that is explicitly outside the deployment boundary.
