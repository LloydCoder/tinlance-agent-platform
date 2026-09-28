# Contributing

Tinlance Agent Platform is a security-sensitive authority substrate. Contributions must preserve the platform boundary rather than merely make a feature work.

## Before changing code

Read, in order:

1. [README.md](README.md)
2. [ARCHITECTURE.md](ARCHITECTURE.md)
3. [docs/ROADMAP.md](docs/ROADMAP.md)
4. [docs/ENTERPRISE-BASELINE.md](docs/ENTERPRISE-BASELINE.md)
5. [AGENTS.md](AGENTS.md)
6. Relevant ADRs and threat models.

## Engineering rules

- Keep changes inside the correct bounded package.
- Preserve `contracts → kernel → services → adapters → apps`.
- Do not add provider SDKs, web frameworks or domain dependencies to contracts/kernel without an explicit architectural decision.
- Never use model output, prompt content, retrieved intelligence, tool registration or evaluation results as authority.
- Preserve tenant isolation and complete mediation.
- Re-authorize consequential side effects immediately before execution.
- Treat unavailable security controls as failures, not permissions.
- Keep secrets out of ordinary model context, evidence and telemetry.
- Add adversarial/failure-path tests for every new security invariant or execution boundary.
- Update threat models and ADRs when the trust boundary changes.
- Reconcile README, roadmap, architecture and enterprise documentation when milestone semantics change.
- Never describe a reference implementation as deployed production infrastructure.
- Do not commit credentials, tokens, private keys, customer data or other secrets.

## Local quality gates

```bash
python -m pip install -e ".[test,security]"
python -m pip check
ruff check .
ruff format --check .
mypy packages
pytest --cov=packages --cov-report=term-missing --cov-fail-under=85
```

Run the PostgreSQL migration/isolation tests when changing database behavior.

## Pull requests

A PR should explain:

- what boundary changed;
- why the change belongs in the platform;
- which security invariants are affected;
- tests and evaluation added/updated;
- documentation/ADR/threat-model changes;
- any production-operator responsibilities introduced.

AI-assisted changes remain subject to human review and project ownership. CI passing is necessary but does not replace security or architectural review.

## License

Contributions to this repository are licensed under the [Apache License 2.0](LICENSE), subject to the repository's contribution terms and any separate written agreement that applies.
