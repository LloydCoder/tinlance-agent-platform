# Security Policy

Tinlance Agent Platform is security-sensitive infrastructure. Do not disclose suspected vulnerabilities in public issues.

## Private reporting

Use GitHub private vulnerability reporting when it is enabled for this repository. If private reporting is unavailable, email hello@tinlance.com with the subject line "Security vulnerability — Tinlance Agent Platform".

Please include:

1. affected component and version or commit;
2. preconditions and attack path;
3. security impact and affected trust boundary;
4. minimal reproduction where safe;
5. suggested remediation, if known.

Do not include credentials, customer data, private keys, production tokens or other secrets in a report.

## Response targets

These are maintainer targets, not guarantees:

| Stage | Target |
|---|---|
| Acknowledge report | Within 2 business days |
| Initial triage | Within 5 business days |
| Status update | At least every 10 business days while active |
| Coordinated disclosure | After validation, remediation and release planning |

Critical issues may be handled faster.

## Security invariants

Security-sensitive changes must preserve:

- deny-by-default authorization;
- immutable tenant scope;
- complete mediation at consequential execution boundaries;
- exact, expiring approval binding;
- parent-to-child authority non-escalation;
- fail-closed isolation;
- execution-only secret handling;
- evidence attribution and integrity;
- sensitive-data-safe observability.

Model output, tool output, retrieved content, peer-agent messages and external intelligence are untrusted. They must never become authority merely because an agent claims they are trusted.

## Verification requirements

Security fixes should include adversarial or regression coverage for the violated invariant. New execution boundaries require tests for authorization, tenancy, approval, isolation, failure behavior and evidence attribution.

See [security/](security/), [tests/conformance/](tests/conformance/), [ARCHITECTURE.md](ARCHITECTURE.md), and [docs/ENTERPRISE-BASELINE.md](docs/ENTERPRISE-BASELINE.md).

## Responsible disclosure

Please allow reasonable time for validation, remediation and coordinated disclosure before publishing vulnerability details. Security fixes may require documentation, threat-model, regression-test and release-artifact changes in addition to code.
