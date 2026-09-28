# Security Policy

Tinlance Agent Platform is security-sensitive infrastructure. Do not disclose suspected vulnerabilities in public issues. Use GitHub private vulnerability reporting when enabled, or the repository's documented private security channel.

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

## Reporting

When reporting a vulnerability privately, include:

1. affected component and version/commit;
2. preconditions and attack path;
3. security impact and affected trust boundary;
4. minimal reproduction where safe;
5. suggested remediation, if known.

Do not include credentials, customer data, private keys, production tokens or other secrets in a report.

## Verification requirements

Security fixes must include adversarial or regression coverage for the violated invariant where practical. New execution boundaries require explicit tests for authorization, tenancy, approval, isolation, failure behavior and evidence attribution.

See `security/` for threat models, `tests/conformance/` for canonical-path checks, [ARCHITECTURE.md](ARCHITECTURE.md) for authority boundaries, and [docs/ENTERPRISE-BASELINE.md](docs/ENTERPRISE-BASELINE.md) for production acceptance controls.

## Responsible disclosure

Please allow reasonable time for validation, remediation and coordinated disclosure before publishing vulnerability details. Security fixes may require changes to documentation, threat models, regression tests and release artifacts in addition to code.
