# ADR-017: Durable workspace snapshots and clean-host restore

- **Status:** Accepted for repository implementation scope; production enablement deferred
- **Date:** 2026-11-09
- **Scope:** Tinlance Agent Platform persistent-computer durability

## Decision

Workspace snapshots are immutable, encrypted, tenant-bound recovery artifacts. A restore is a new execution on a clean destination under a strictly newer, currently active workspace fencing token. Snapshot data never carries forward execution authority.

The implementation separates five concerns:

1. **Snapshot service** validates canonical paths, file types, sizes, modes, tenant/workspace identity, authenticated provenance and restore preconditions.
2. **Cipher and signer contracts** separate encryption and integrity keys from snapshot logic.
3. **Object store** persists opaque encrypted bytes. The local filesystem adapter is for tests and controlled development; the S3 adapter uses conditional creation and SSE-KMS.
4. **PostgreSQL catalog and restore ledger** persist tenant-scoped metadata, idempotency claims, one-way state transitions and append-only events.
5. **Lease authority and credential refresher** prove current authority and reacquire opaque secret references after materialization.

## Cryptographic controls

Production deployments must use KMSAESGCMCipher with a dedicated AWS KMS symmetric encryption key and KMSSnapshotSigner with a separate KMS HMAC-256 key. The encryption adapter requests a fresh AES-256 data key for each snapshot, encrypts the snapshot with AES-256-GCM, and stores only the KMS-wrapped data key beside the ciphertext. KMS encryption context binds the wrapped data key to a SHA-256 digest of the tenant/workspace/snapshot associated data. The GCM AAD independently authenticates that same provenance.

The signing adapter uses KMS GenerateMac / VerifyMac with HMAC_SHA_256. Encryption and signing keys must be separate. Key ARNs are configuration, not snapshot content. KMS key policies and IAM grants must be least-privilege and environment-specific. Rotation must preserve decrypt/verify access to historical key versions for the configured snapshot retention period.

AESGCMCipher and HMACSnapshotSigner are test/development adapters that accept caller-supplied key bytes. They are not the production key-management configuration.

## Object storage

Use S3SnapshotStore for production object storage. It:
- writes to a normalized, versioned prefix;
- uses If-None-Match: * to prevent overwriting an existing snapshot ID;
- requires S3 server-side encryption with the configured KMS key;
- validates object metadata and bounds the read size;
- exposes no overwrite or delete operation.

The S3 bucket must be provisioned separately with Block Public Access, TLS-only bucket policy, versioning, access logging, lifecycle/retention controls, and (where required by the data-retention policy) S3 Object Lock. The adapter does not silently create or weaken bucket policy, retention or Object Lock settings. Configure replication and recovery of the bucket and KMS keys independently.

FilesystemSnapshotStore is for tests and controlled local deployments only. It is not a multi-host production object store.

## Snapshot contents and exclusions

The service captures only a caller-supplied manifest of regular workspace files. It rejects traversal, non-canonical paths, credential directories and common authentication artifacts (.aws, .ssh, .kube, .env*, browser cookies/login databases, token and private-key files). Per-file and total size limits are enforced; restored file modes are allowlisted.

The caller is responsible for enumerating files without following symlinks and for applying an explicit workspace allowlist before passing file bytes to the service. Do not pass an entire home directory or browser profile root. Browser profile data that is safe and necessary must be curated; authentication state is never restored.

## Tenant and authority invariants

- The snapshot reference authenticates tenant_id, workspace_id, snapshot_id, fencing_token, schema version and digest.
- PostgreSQL catalog writes and restore claims require the matching current, active, unexpired lease fencing token.
- Snapshot and restore metadata are protected by forced row-level security and tenant-scoped database functions.
- Snapshot and restore event tables are append-only.
- Restore IDs are one-shot. Duplicate claims are rejected. Completion/failure transitions are terminal and idempotent only when the repeated result matches the original terminal value.
- Restore requires a fence strictly greater than the snapshot fence, checks lease authority before work and immediately before publication, and uses a clean destination with a private staging directory.
- Credentials are reacquired after materialization through CredentialRefresher. Only opaque secret-ref:// or Secrets Manager ARN references may be returned; secret values, tokens and private keys are not serialized into snapshots.
- A restored filesystem never restores the prior lease, worker identity, credentials, approvals, policy grants, budget reservations, or authorization decisions.

## Publication and ambiguous acknowledgements

The restored tree is materialized in a private staging directory and atomically published only after content verification, credential refresh and a second active-lease check. The ledger completion transition is retried once and is idempotent for the same digest.

If the database acknowledgement remains ambiguous after publication, the published tree is retained rather than destructively removed. The restore remains an operational reconciliation case; operators must compare the restore ledger, destination manifest digest and audit events before allowing a new restore attempt. Never delete an atomically published tree solely because a database response was lost.

## Operational requirements before production enablement

- Provision dedicated KMS encryption and HMAC keys; configure key policies, IAM permissions, CloudTrail data events and key rotation.
- Provision S3 with Block Public Access, TLS-only access, versioning, access logging, lifecycle and required Object Lock retention.
- Run database migrations and SQL acceptance tests through the production migration process; grant the application database role only the required function/table permissions.
- Configure a durable PostgreSQL connection factory and S3 client using workload identity/instance roles, not static access keys.
- Configure a bounded snapshot retention policy, storage budget, backup/restore drills and a reconciler for started restore operations whose completion acknowledgement was ambiguous.
- Monitor snapshot create/restore failures, age of started restore claims, KMS throttling/errors, S3 errors, bytes stored and restore duration.
- Perform a full cross-AZ or cross-region recovery drill before claiming disaster-recovery readiness.

## Validation

W6 acceptance is not inferred from unit tests alone. Required evidence includes the full Python CI matrix, migration application on the supported PostgreSQL major version, all database acceptance tests, tenant-isolation tests under a non-superuser runtime role, and a clean-host restore drill proving a new fence and refreshed credentials. Production GA additionally requires the operational prerequisites above and independent certification.
