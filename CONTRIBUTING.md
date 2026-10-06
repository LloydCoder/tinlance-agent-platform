# Contributing

Tinlance Agent Platform is a security-sensitive authority substrate. Contributions must preserve the platform boundary, not merely make a feature work.

## Before you change code

Read these in order:

1. [README.md](README.md)
2. [ARCHITECTURE.md](ARCHITECTURE.md)
3. [docs/ROADMAP.md](docs/ROADMAP.md)
4. [docs/ENTERPRISE-BASELINE.md](docs/ENTERPRISE-BASELINE.md)
5. [AGENTS.md](AGENTS.md)
6. Relevant ADRs and threat models.

## Development workflow

1. Fork the repository and clone your fork.
2. Create a focused branch from main.
3. Make the smallest coherent change.
4. Add or update executable tests, especially failure-path and security tests.
5. Run the local quality gates.
6. Update documentation, ADRs, threat models and changelog entries affected by the change.
7. Open a pull request using the repository template.

Keep commits focused. Conventional Commit style is recommended, for example feat:, fix:, docs:, test:, refactor:, chore:, or security:.

## Engineering rules

- Keep changes inside the correct bounded package.
- Preserve contracts → kernel → services → adapters → apps.
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

~~~bash
python -m pip install -e ".[test,security]"
python -m pip check
ruff check .
ruff format --check .
mypy packages
pytest --cov=packages --cov-report=term-missing --cov-fail-under=85
~~~

For database changes, also run the PostgreSQL migration and isolation tests under database/tests/.

## Pull requests

Every PR should explain:

- what changed and why it belongs in the Platform;
- which package or contract owns the change;
- whether a trust boundary changed;
- which security invariants are affected;
- tests and evaluation added or updated;
- documentation, ADR and threat-model changes;
- any production-operator responsibilities introduced.

CI passing is necessary but does not replace architectural or security review.

## Review expectations

Changes affecting identity, authorization, policy, approvals, sandboxing, secrets, evidence, runtime side effects, MCP, remote-agent trust or release provenance require explicit security reasoning and regression coverage.

## License

Contributions are licensed under the [Apache License 2.0](LICENSE), subject to any separate written agreement that applies.
