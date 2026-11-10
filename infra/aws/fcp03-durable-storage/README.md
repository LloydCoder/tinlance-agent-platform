# FCP-03 durable identity and snapshot storage stack

This CloudFormation template is a **deployment candidate**, not a deployed production service. It is separate from Tinlyt, FusionOps, ThreatFade and the disposable egress lab.

## Resources

- A symmetric KMS key for DynamoDB encryption and S3 snapshot envelope/storage encryption, with automatic rotation and workload-role use constrained to the relevant AWS services and table/object encryption contexts.
- A separate KMS HMAC-256 key for workspace snapshot signing.
- On-demand DynamoDB tables for token revocation and DPoP replay records. Both have TTL on `expires_at`, point-in-time recovery, and customer-managed KMS encryption.
- A versioned S3 snapshot bucket with S3 Object Lock in COMPLIANCE mode, configurable default retention, SSE-KMS, bucket-owner-enforced ownership, public-access blocking, TLS-only access, exact snapshot-prefix write policy and version-deletion denial.
- A separate S3 server-access-log destination with bucket-owner-preferred ownership (ACLs enabled for log delivery), SSE-S3, public-access blocking, source-account/source-bucket-scoped delivery policy, one-year current-log expiry and 30-day noncurrent-version expiry. The log destination is retained with the stack's other durable resources.
- A detached IAM managed policy scoped to the two DynamoDB tables, the snapshot prefix and the two KMS keys.

The table partition keys match the low-level adapters:
- Token revocation: `revocation_key`
- DPoP replay: `replay_key`

The S3 prefix matches `S3SnapshotStore`'s default `tinlance/workspace-snapshots/v1` prefix.

## Deployment prerequisites

1. Create and independently review a dedicated workload IAM role. The exact role ARN must exist before stack creation because it is named in both KMS key policies.
2. Review the generated managed policy and attach it only to that workload role. The stack deliberately does not attach permissions to an arbitrary role automatically.
3. Confirm the DynamoDB adapters' table names and schema settings against the deployed table outputs.
4. Configure the snapshot adapter with the bucket output, data-key ARN and HMAC signing-key ARN.
5. Verify KMS key policies, IAM effective permissions, S3 Object Lock configuration, DynamoDB TTL/PITR status, CloudTrail coverage, alarms, backup/restore and recovery procedures.
6. Run real cross-tenant, revocation-propagation, replay-race, snapshot integrity and restore drills before production use.

## Irreversible retention and cost warning

The bucket uses COMPLIANCE-mode Object Lock. Objects cannot be shortened or deleted during the retention period, including by the account root user. The bucket, tables and keys use `DeletionPolicy: Retain`; deleting the stack does not remove the retained data or stop its storage/key charges. The stack creates two KMS keys, two DynamoDB tables and an S3 bucket. DynamoDB is on-demand, but requests and stored data are billable; KMS keys and S3 storage/requests are also billable.

**Do not deploy under the current zero-new-AWS-spend constraint.** This template has not been deployed, and no CloudFormation validation or live IAM/KMS/S3/DynamoDB acceptance is claimed. It does not create the production PostgreSQL/outbox/queue, host-attestation, browser isolation, telemetry backend, alerting or cross-region disaster-recovery systems. It is one infrastructure slice of FCP-03, not phase completion.
