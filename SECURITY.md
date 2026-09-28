# Security Policy

Do not disclose suspected vulnerabilities in public issues. Use GitHub private vulnerability reporting when enabled.

Model output, tool output and external content are untrusted. Authority is established outside model reasoning and enforced at execution boundaries.

Never commit credentials, tokens, private keys, production data or customer secrets.

## Reporting and verification

Security-sensitive changes must preserve deny-by-default behavior, tenant isolation, complete mediation, approval binding and evidence attribution. New execution boundaries require adversarial tests. See `security/` for the threat models and `tests/conformance/` for the executable canonical-path checks.
