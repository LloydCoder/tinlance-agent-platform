# P7 — Real Adapters and Integration Boundaries

**Status: in progress; not certified.** Canonical ecosystem P7 is distinct from repository-local P7 filenames and TSIC phase numbers.

## Authority and boundary

The Platform remains the only authority for identity, authorization, policy, approval, budget, sandbox, secret scope, route selection, and consequential execution. An adapter is a transport boundary, not a policy engine. OS and SDK callers must use the versioned Platform contract; they must not call a provider or tool in a way that bypasses Platform mediation.

## Provider adapter contract

The Platform's OpenAI-compatible chat-completions adapter implements the existing provider-neutral `ModelProvider` protocol. Its endpoint and credential provider are explicit trusted configuration. It enforces HTTPS except for explicitly enabled loopback tests, rejects URI-embedded credentials and redirects, bounds request and response sizes, applies a finite timeout, validates trace identifiers and response structure, normalizes provider failures without echoing response bodies or credentials, and rejects unexpected model identifiers or invalid token usage.

The adapter deliberately does not retry provider calls automatically. A timeout or connection failure can occur after a provider has accepted and billed a request; automatic retries could duplicate cost or effects. It marks retryable transport/status errors so a higher-level Platform policy can decide whether a bounded retry is safe. Provider requests do not include tenant or agent identifiers; only a validated W3C `traceparent` is propagated. A trace ID alone is not sent as a non-standard substitute for a full trace context.

Credentials are injected via a protocol. `StaticModelCredential` is suitable for tests or caller-managed short-lived credentials; production must use a secret-manager-backed implementation. No live provider credential or external production connection is asserted by repository tests.

## Exit gate

P7 can be certified only after all items are evidenced:

- [ ] Platform adapter tests cover successful normalization, provider HTTP failures, malformed responses, size/time limits, redirects, URI credentials, trace validation and secret/personal-context minimization.
- [ ] SDK and OS integration boundaries preserve API version, authenticated context, request idempotency, trace lineage, bounded timeouts, cancellation semantics and normalized errors.
- [ ] Cancellation and retry semantics distinguish safe idempotent requests from ambiguous consequential operations; no adapter retries an ambiguous operation by default.
- [ ] Cross-repository contract tests exercise deterministic provider-compatible endpoints and reject tenant/authority spoofing, redirects, malformed payloads and response-size exhaustion.
- [ ] TSIC integration contract and conformance fixtures describe the adapter boundary without claiming that a real provider or production credential exists.
- [ ] The exact four-repository SHAs and TSIC authority revision are pinned in the lock and manifest; all CI/security/integration workflows pass on PR heads and merge commits.
- [ ] The post-merge forensic audit reconciles code, tests, contracts, workflow evidence and residual risk.

Passing local or deterministic endpoint tests proves reference adapter behavior only. Live external provider access, secret-manager integration, deployed networking, telemetry, quotas and production incident controls remain unverified until independently evidenced.
