# M10 Evidence/Event Threat Model

## Assets
Audit history, evidence provenance, trajectory integrity and event ordering.

## Threats
- evidence tampering;
- cross-tenant reads;
- sequence manipulation;
- duplicate event replay;
- secret leakage into evidence or events;
- model claims being mistaken for authoritative findings.

## Required controls
Evidence is content-addressed and tenant/run scoped. Trajectory uses a hash chain. Event stores reject invalid tenant identity and preserve append-only semantics. Evidence consumers must preserve the distinction observation != evidence != finding != verdict.
