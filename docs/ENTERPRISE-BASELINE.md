# Enterprise Baseline

## Security references

Current agent guidance separates trusted harness/control-plane responsibilities from sandbox compute, recommends human review before sensitive side effects, and emphasizes tracing/evaluation. OWASP highlights excessive agency, excessive permissions, prompt injection, tool abuse, memory poisoning, data exfiltration and approval manipulation. NIST AI RMF emphasizes governance, auditing, documentation, human oversight and lifecycle evaluation. PostgreSQL RLS requires explicit policies and is distinct from SQL privileges and referential integrity.

## Enterprise controls

Authority: principal identity is explicit; tenant is immutable; capabilities are not authority; prohibited capabilities are never executable; tool execution re-authorizes immediately before side effects; child agents receive only subsets of parent authority.

Human control: high-risk, irreversible, sensitive/restricted or broad-blast-radius actions pause for approval; approval is bound to tenant, run, action and resource; expiry fails closed.

Isolation: sandbox availability is mandatory for governed execution; commands and workspace paths are allowlisted; network is denied by default; host-sensitive paths are rejected; Bubblewrap uses namespace isolation and private temporary storage. Production supervisors must enforce CPU, memory, disk, process and output limits.

Data: memory is tenant scoped; untrusted context is excluded by default; secret-like material is redacted; secrets resolve through execution-only handles; evidence and audit carry tenant/run attribution.

Persistence: PostgreSQL migrations enforce tenant RLS and cross-tenant composite foreign keys. Evidence, trajectory and audit surfaces are append-only by policy and grants. RLS is defense in depth, not a replacement for application authorization.

Observability: telemetry carries tenant, run, trace and outcome metadata. Sensitive prompt/tool content is not required for telemetry.

Evaluation: safety-critical regressions fail the evaluation run. Evaluation never grants runtime authority.

## Production acceptance checklist

- Dedicated non-superuser application role with no BYPASSRLS.
- PostgreSQL migrations and integrity/RLS tests pass.
- Durable repositories and transactional outbox worker deployed.
- External secret manager with rotation and audit deployed.
- Least-privilege model/tool/MCP providers configured.
- Linux sandbox verified on the production runtime.
- Process, CPU, memory, disk and output limits enforced by the supervisor.
- OpenTelemetry collector/exporter and alerting configured.
- Backups and restore drills verified.
- Incident-response and security-event retention policy approved.
- Domain SDK consumers pass compatibility/conformance tests.
- FAS/FAS-Bench and FDSE integration tests run in their own repositories; platform remains independent.

## Hardening status

The repository's reference execution path enforces real wall-clock deadlines rather than relying only on post-hoc elapsed-time checks. The POSIX sandbox adapter also has a process supervisor with wall-clock, address-space, file-size and process-count ceilings and kills the entire process group on timeout.

The repository still cannot prove deployment of external infrastructure from CI alone. Production acceptance therefore requires the deployment operator to verify the non-superuser database role, durable persistence/outbox, external secret manager, sandbox runtime, telemetry, backups and restore drills listed above. These are deployment gates, not claims of repository completeness.

A repository can be enterprise-grade in architecture and controls without claiming infrastructure outside the repository has already been deployed.
