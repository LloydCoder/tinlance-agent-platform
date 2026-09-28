# Dependency and Consumer Audit

Agent Platform is a standalone generic substrate. FDSE, TADS, ThreatFade, ReconOS, FadeReach and Hezqara remain consumers.

## Reuse policy

FDE Mastery is reference material only. Generic concepts may be reimplemented behind clean contracts; domain-specific code and direct package coupling do not migrate into the kernel.

## M0 boundary

The platform currently owns:
- provider-neutral contracts
- authority/tenant invariants
- identity validation
- authorization
- deterministic risk policy

Future runtime, model/tool, sandbox, event, evidence and observability capabilities must be introduced as bounded packages with tests and adapters.

## Architectural conclusion

Do not recreate a `common` dumping ground and do not copy an entire external platform-core. Every dependency must have an explicit direction and owner.
