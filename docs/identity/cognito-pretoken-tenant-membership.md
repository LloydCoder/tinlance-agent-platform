# Cognito V2 Pre Token Generation: trusted tenant membership

## Purpose

The Tinlyt Platform requires a tenant claim in every human-user access token. Cognito does not
provide a trustworthy tenant assignment by default. The V2 Pre Token Generation handler adds
`tenant_id` and the constant `principal_type=user` only after it resolves the authenticated
Cognito subject against a server-controlled membership table.

The handler never reads tenant identity from browser parameters, OAuth client metadata, email
domains, or mutable profile attributes. A missing, inactive, malformed or unavailable membership
record prevents token issuance.

## Cognito trigger configuration

- Use a dedicated Tinlyt user pool in the selected AWS Region.
- Configure the Essentials or Plus feature plan and select Pre Token Generation event version
  `V2_0` (access-token customization for human users).
- Associate the Lambda function with the exact user-pool ARN. Add a Lambda resource policy that
  permits `cognito-idp.amazonaws.com` to invoke only this function from that exact pool ARN and
  AWS account.
- Use authorization-code grant with PKCE S256 for the browser app. Do not enable implicit grant.
- The handler allowlists the exact app-client IDs. Preview and production clients must be separate
  entries and must match the Platform access-token verifier configuration.
- The handler accepts the documented human-user trigger sources: HostedAuth, Authentication,
  NewPasswordChallenge, AuthenticateDevice and RefreshTokens. It rejects ClientCredentials; that
  flow requires a V3 event and is not part of this human-user profile.

## Membership table contract

Create a dedicated table with:

| Setting | Value |
| --- | --- |
| Partition key | `subject_key` (String) |
| Sort key | None |
| Billing mode | On-demand for low/variable beta traffic |
| Point-in-time recovery | Enabled |
| Deletion protection | Enabled |
| Encryption | DynamoDB encryption at rest; CMK only after cost approval |

The partition key is SHA-256 of the user-pool ID and Cognito `sub`, separated by a NUL byte. Each
record also stores the source `user_pool_id` and `subject_id`; the resolver verifies both on every
read. This avoids cross-pool collisions and prevents a malformed row from binding one user to
another user's tenant.

A membership record has this shape:

```json
{
  "subject_key": "<sha256(user_pool_id + NUL + sub)>",
  "user_pool_id": "eu-west-1_Abc123",
  "subject_id": "<cognito-sub>",
  "tenant_id": "tenant-prod-01",
  "status": "active"
}
```

The initial rollout supports one active tenant per Cognito subject. A disabled or absent record
fails closed. Multi-tenant account switching requires a separate server-authorized membership
selection flow; never accept a tenant ID from the browser.

## Runtime wrapper

Install the optional runtime extra. Initialize the SDK client and handler outside the Lambda
function so warm invocations reuse the client:

```bash
pip install '.[aws-runtime]'
```

```python
import os

import boto3
from botocore.config import Config

from tinlance_agent_platform_identity import (
    CognitoPreTokenGenerationV2Handler,
    DynamoDBTenantMembershipResolver,
)

region = os.environ["AWS_REGION"]
user_pool_id = os.environ["COGNITO_USER_POOL_ID"]
allowed_client_ids = frozenset(
    value for value in os.environ["COGNITO_APP_CLIENT_IDS"].split(",") if value
)
table_name = os.environ["TENANT_MEMBERSHIP_TABLE"]

sdk_config = Config(
    connect_timeout=1,
    read_timeout=1,
    retries={"mode": "standard", "total_max_attempts": 2},
)
dynamodb = boto3.resource("dynamodb", region_name=region, config=sdk_config)
membership_resolver = DynamoDBTenantMembershipResolver(
    dynamodb.meta.client,
    table_name=table_name,
    user_pool_id=user_pool_id,
)
pre_token_handler = CognitoPreTokenGenerationV2Handler(
    membership_resolver,
    user_pool_id=user_pool_id,
    allowed_client_ids=allowed_client_ids,
)


def lambda_handler(event, context):
    return pre_token_handler.handle(event)
```

The DynamoDB resource's `meta.client` uses boto3's resource marshalling handlers. The function
performs one strongly consistent `GetItem` per token issuance and does not cache tenant
membership across invocations, so administrative revocation takes effect on the next issuance.

## Least-privilege IAM

The Lambda execution role needs only `dynamodb:GetItem` on the exact membership table ARN.
It must not have `PutItem`, `UpdateItem`, `DeleteItem`, `Scan`, `Query`, `TransactWriteItems`,
or wildcard DynamoDB permissions. Membership provisioning belongs to a separate administrative
control plane with a separate role and audit trail.

## Failure and security behavior

- Event version must be exactly `2`; unsupported trigger sources and unapproved app clients are
  rejected.
- The configured user-pool ID must match the event's pool.
- The subject comes only from Cognito's authenticated `request.userAttributes.sub`.
- Membership reads use `ConsistentRead=True`.
- The record's subject, pool, status and tenant ID are validated.
- `tenant_id` and `principal_type=user` are added only under
  `response.claimsAndScopeOverrideDetails.accessTokenGeneration.claimsToAddOrOverride`.
- Existing access-token claims and scope overrides are preserved. ID-token claims and group
  configuration are not modified.
- `clientMetadata`, custom user attributes and email are ignored.
- DynamoDB errors and malformed events fail token generation. Do not catch these errors and issue
  a token without tenant claims.
- Do not log the full Cognito event, user attributes, bearer tokens or refresh tokens.

## Operations

Set Lambda timeout and memory deliberately, initialize SDK clients outside the handler, and set
bounded SDK connection/read timeouts with a small retry budget. Configure alarms for Lambda errors,
throttles and duration, plus DynamoDB read throttles/errors. Set CloudWatch log retention. The
membership table should have PITR and deletion protection because loss or accidental deletion of
membership state can affect tenant isolation.

## Not provisioned by this code

This package and document do not create the DynamoDB table, Lambda function, execution role,
Cognito user pool, app client, trigger association, Lambda invoke permission, DNS record or API.
Provisioning remains gated on current AWS credits, a verified spend ceiling and least-privilege
deployment credentials.

## References

- Cognito Pre Token Generation trigger: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html
- Cognito Lambda trigger integration: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-working-with-lambda-triggers.html
- Cognito feature plans: https://docs.aws.amazon.com/cognito/latest/developerguide/feature-plans-features-essentials.html
