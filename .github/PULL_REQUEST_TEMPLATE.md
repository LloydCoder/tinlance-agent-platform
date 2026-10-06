## Summary

Describe the change and why it belongs in Tinlance Agent Platform.

## Boundary impact

- Package(s):
- Contract(s):
- Trust boundary changed? Yes / No
- New external/provider dependency? Yes / No

## Security and governance

- [ ] Tenant isolation reviewed
- [ ] Authorization and complete mediation reviewed
- [ ] Approval semantics reviewed where applicable
- [ ] Secrets remain execution-only
- [ ] Evidence and audit behavior reviewed
- [ ] Failure paths are fail-closed where required

## Validation

- [ ] python -m pip check
- [ ] ruff check .
- [ ] ruff format --check .
- [ ] mypy packages
- [ ] pytest --cov=packages --cov-report=term-missing --cov-fail-under=85
- [ ] Relevant PostgreSQL tests run for database changes
- [ ] Relevant adversarial/security tests added or updated

## Documentation

- [ ] README/docs updated
- [ ] ADR updated if architecture or trust boundary changed
- [ ] Threat model updated if a security boundary changed
- [ ] CHANGELOG entry added for user-visible changes

## Production claims

- [ ] No repository-level test is described as proof that external production infrastructure is deployed.
