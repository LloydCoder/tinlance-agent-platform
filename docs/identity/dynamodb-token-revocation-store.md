# DynamoDB token-revocation store

## Purpose

The Platform uses revocation state as an authorization control, not merely an audit record. Every
authenticated request checks the verified access-token `jti` and any configured token-family
identifier such as Cognito `origin_jti`. Session sign-out must persist both identifiers atomically
before returning success.

`DynamoDBTokenRevocationStore` is the shared multi-instance implementation. The SQLite store
remains a local reference implementation and is not suitable for a horizontally scaled service.

## Table contract

Create one table dedicated to the Platform revocation store:

| Setting | Value |
| --- | --- |
| Partition key | `revocation_key` (String) |
| Sort key | None |
| TTL attribute | `expires_at` (Number, Unix epoch seconds) |
| Billing mode | On-demand for low/variable beta traffic |
| Encryption | DynamoDB encryption at rest; select a customer-managed KMS key only after cost approval |
| Recovery | Point-in-time recovery enabled; deletion protection enabled |
| Backups | Include the table in the production backup policy |

The partition key is a SHA-256 digest of the issuer and token ID, separated by a NUL byte. This
distributes writes across partition-key values instead of placing every token from one Cognito
issuer into a single hot partition. Each item also stores the original issuer and token ID; reads
verify that they match the lookup to detect malformed records.

## Write and read semantics

- `revoke_identity` writes the access-token ID and every configured family ID in one
  `TransactWriteItems` call. The transaction is atomic: no partial family revocation is accepted.
- Access-token records expire at the verified JWT `exp` plus the configured token retention
  interval (default 10 minutes).
- Family records expire at revocation time plus `family_retention_seconds` (default 31 days).
  This must be greater than or equal to the Cognito refresh-token validity configured for the app
  client. If refresh-token validity changes, increase this retention before deploying the change.
- `is_revoked` uses `GetItem(ConsistentRead=True)`. It returns false only when no record exists
  or the record's TTL has passed. Missing/malformed TTL data, issuer/token mismatch, and all AWS
  service errors propagate so `JWKSPrincipalResolver` can fail closed.
- DynamoDB TTL deletion is asynchronous. The adapter checks `expires_at` itself and does not
  depend on prompt physical deletion.
- Do not use eventual-consistency reads, scans, batch writes, or separate non-transactional puts
  for token-family revocation.

## Runtime construction

Install the optional runtime extra and create the DynamoDB resource client once at process startup:

```bash
pip install '.[aws-runtime]'
```

```python
import boto3

from tinlance_agent_platform_identity import DynamoDBTokenRevocationStore

dynamodb = boto3.client("dynamodb", region_name="eu-west-1")
revocations = DynamoDBTokenRevocationStore(
    dynamodb,
    table_name="tinlyt-platform-token-revocations",
    token_retention_seconds=600,
    family_retention_seconds=31 * 24 * 60 * 60,
)
```

The adapter accepts boto3's low-level DynamoDB client and performs explicit
`AttributeValue` serialization/deserialization for its string and numeric fields. A
`Table.meta.client` is also a low-level client; it does not provide automatic Python-type
marshalling. Do not pass a `Table` resource itself. The adapter requires the low-level client's
`GetItem` and `TransactWriteItems` operations.

Pass the same store instance as both the `JWKSPrincipalResolver` revocation checker and its
session-revocation writer. The API must return success only after the transaction completes.

## Least-privilege IAM

The runtime role needs only these data-plane actions on the exact table ARN:

- `dynamodb:GetItem`
- `dynamodb:TransactWriteItems`

Do not grant `dynamodb:Scan`, `dynamodb:Query`, `dynamodb:PutItem`, `dynamodb:DeleteItem`,
`dynamodb:UpdateItem`, `dynamodb:*`, or wildcard resources. Table creation, TTL configuration,
PITR, backups and deletion protection belong to a separate infrastructure deployment role, not
the application runtime role.

## Operational requirements

- Alarm on transaction throttling, read/write errors, transaction cancellations, and elevated
  authorization failures.
- Treat revocation-store latency and availability as authentication-path SLOs.
- Keep the family retention interval synchronized with the configured Cognito refresh-token
  validity; add a deployment assertion so the two cannot drift silently.
- Do not log bearer tokens or raw refresh tokens. Log only the validated request ID, issuer
  identifier, and a one-way digest of the token identifier where correlation is needed.
- Restore tests must prove that revoked tokens remain revoked after table recovery.
- No table is created by this code change. Provisioning remains gated on the verified AWS credit
  balance, a least-privilege deployment role, and explicit cost approval.
