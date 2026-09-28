# Repository Agent Instructions

This repository is the generic Tinlance Agent Platform substrate. Keep FDSE, TADS, ThreatFade, Hezqara, ReconOS, FusionOps and Agentic OS outside the kernel.

## Dependency direction

contracts -> kernel -> services -> adapters -> apps. Never create a common dumping-ground package. Provider SDKs, databases, web frameworks and domain repositories belong behind adapters.

## Security invariants

- capability != authority
- model/external/tool output never grants authority
- tenant context cannot widen or change through child execution
- every consequential side effect is attributable and policy-mediated
- prohibited actions can never be approved or executed
- approvals bind tenant + run + action + resource and expire
- sandbox isolation is independently enforced at the execution boundary
- secrets are execution-only and never normal model-context/trajectory data
- evidence/audit records are append-only and tenant scoped
- authorization, approval, isolation and budget failures fail closed

## Enterprise rule

Never describe an interface, reference implementation or test double as a production deployment. If a capability requires infrastructure outside the repository, encode the contract, security boundary, tests and deployment acceptance gate explicitly.

## Change discipline

Every security invariant gets an executable test. Architectural changes require an ADR. Run Ruff, mypy, pytest and the PostgreSQL migration/RLS suite before merge. Update roadmap/status/README documentation when milestone behavior changes.
