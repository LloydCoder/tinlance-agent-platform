# M21 — Production Infrastructure

## Objective

Turn the M19 production boundary into an explicit, evidence-backed readiness contract without introducing provider-specific infrastructure into the Platform core.

## Readiness dependencies

M21 tracks seventeen independently evidenced production control dependencies:

1. durable database;
2. transactional outbox/queue delivery;
3. external secret manager;
4. isolated sandbox/runtime;
5. telemetry backend;
6. backup capability;
7. incident-response controls;
8. provider-attested hardware/firmware/microcode/SMT posture;
9. destination-level egress enforcement independent of the browser proxy;
10. explicit DNS query policy;
11. live identity and revocation propagation;
12. encrypted durable browser/workspace profile storage;
13. production CPU, memory, process and storage resource isolation;
14. disaster-recovery and restore qualification;
15. spend limits, budget/credit coverage and cost reconciliation;
16. independent security assessment and residual-risk disposition;
17. named operational ownership.

A verified dependency must have an evidence reference. Missing or unverified dependencies block production readiness.

## Boundary

The readiness contract is a certification surface, not a provisioning engine. PostgreSQL, KMS, secret managers, queues, telemetry systems, sandbox supervisors and cloud infrastructure remain deployment-specific adapters.

## Evidence record requirements

Each dependency kind must appear exactly once in a readiness record. A verified record must bind:

- normalized deployment environment (for example, `production` or `staging`);
- durable evidence URI using `https`, `s3` or the internal `evidence` scheme;
- named verifier and timezone-aware verification timestamp;
- lowercase SHA-256 digest of the evidence bytes;
- optional expiry later than the verification timestamp.

Readiness verification rejects duplicate or missing dependency kinds, unverified dependencies, environment mismatches, future-dated evidence and expired evidence. Evidence URIs cannot contain embedded credentials, query strings or fragments; use stable evidence object references, not signed URLs or secret-bearing links. A production readiness record must be evaluated against the matching environment.

The contract validates evidence metadata and consistency. It does not fetch evidence bytes, verify the digest against an external object, provision dependencies, or prove that an operator's attestation is truthful. Independent reviewers and deployment automation must verify the referenced evidence and preserve its immutable provenance.

## Completion evidence

M21 is complete only when the readiness contract, tests, deployment documentation, architecture/conformance documentation and every CI/security workflow are green.
