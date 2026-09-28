# M10 Evidence/Event Threat Model

## Abuse cases

- Evidence is attributed to the wrong tenant or run.
- Existing evidence or events are overwritten/deleted.
- Hashes do not match content.
- Sequence numbers can be reordered or duplicated.
- Sensitive secrets are copied into telemetry/evidence.
- Model output is represented as an authoritative verdict without provenance.

## Controls

Evidence and events are tenant/run scoped, append-only by policy, content-addressed or integrity-verifiable, and emitted with actor/trace/outcome metadata. Sensitive fields are rejected or redacted. Provenance must distinguish observations, evidence, findings and verdicts; evaluation cannot grant authority.

## Test obligations

Cross-tenant reads, duplicate append, content mutation, sequence corruption, sensitive-field rejection and provenance/authority separation must be covered by executable tests.
