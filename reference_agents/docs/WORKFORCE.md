# P9 — Reference Enterprise Workforce

P9 establishes a reference enterprise workforce of eleven governed roles:

Executive, Research, Finance, Security, Engineering, Sales, Marketing, Operations, Customer Success, Procurement, and Compliance.

Each role is an immutable, deterministic reference profile with:

- a stable lowercase hyphenated role identity;
- business function and mission;
- a unique, ordered capability vocabulary;
- an explicit human escalation target;
- an authority-free serialization suitable for catalog inspection.

These profiles are **reference compositions, not privileged principals**. A role identifier, capability string, catalog entry, model output, or escalation target never grants execution authority. Platform identity, tenancy, authorization, policy, approvals, budgets, sandboxing, secrets, and evidence remain authoritative.

## Organizational operating model

Roles are intended to compose through Agent OS workspaces, tasks, workflows, teams, and governed Platform execution. Cross-role handoffs must preserve tenant, task, trace, evidence, and authority context.

A role may describe what a workforce function is expected to do; it may not authorize itself or another role. Any consequential action must traverse the Platform authority boundary.

## Catalog invariants

The reference catalog enforces:

1. exactly one stable role identity per role;
2. canonical lowercase hyphenated identifiers;
3. non-empty normalized mission/function/escalation metadata;
4. unique capabilities within each role;
5. immutable role objects;
6. deterministic catalog ordering;
7. lookup by stable role ID;
8. serialization containing descriptive metadata only, never policy or authorization state.

These are repository-level invariants and do not replace runtime authorization.

## Exit criterion

P9 is complete when the reference workforce catalog is represented, tested, documented, deterministic, and capable of being composed without introducing a second authority plane.

The next ecosystem phase must prove the workforce through an end-to-end reference-enterprise transformation rather than treating the catalog itself as evidence of operational capability.
