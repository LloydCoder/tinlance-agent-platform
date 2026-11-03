from __future__ import annotations

import copy
import hashlib
from typing import Any

import pytest

from tinlance_agent_platform_identity import (
    CognitoPreTokenGenerationV2Handler,
    CognitoTenantMembershipError,
    DynamoDBTenantMembershipResolver,
    build_cognito_pretoken_handler,
)

USER_POOL_ID = "eu-west-1_Abc123"
CLIENT_ID = "tinlytwebclient123"
SUBJECT_ID = "cognito-user-123"
TABLE_NAME = "tinlyt-user-tenant-memberships"


class FakeMembershipClient:
    def __init__(self) -> None:
        self.items: dict[str, dict[str, object]] = {}
        self.calls: list[dict[str, object]] = []
        self.fail_read = False

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        if self.fail_read:
            raise OSError("DynamoDB membership lookup unavailable")
        self.calls.append(kwargs)
        key = str(kwargs["Key"]["subject_key"])
        item = self.items.get(key)
        return {"Item": dict(item)} if item is not None else {}


def membership_key(user_pool_id: str, subject_id: str) -> str:
    return hashlib.sha256(f"{user_pool_id}\0{subject_id}".encode()).hexdigest()


def active_membership(
    client: FakeMembershipClient,
    *,
    user_pool_id: str = USER_POOL_ID,
    subject_id: str = SUBJECT_ID,
    tenant_id: str = "tenant-prod-01",
    status: str = "active",
    capabilities: tuple[str, ...] = ("web.search", "web.fetch"),
) -> None:
    key = membership_key(user_pool_id, subject_id)
    client.items[key] = {
        "subject_key": key,
        "user_pool_id": user_pool_id,
        "subject_id": subject_id,
        "tenant_id": tenant_id,
        "status": status,
        "capabilities": list(capabilities),
    }


def make_event(**overrides: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "version": "2",
        "triggerSource": "TokenGeneration_HostedAuth",
        "region": "eu-west-1",
        "userPoolId": USER_POOL_ID,
        "callerContext": {
            "awsSdkVersion": "aws-sdk-unknown-unknown",
            "clientId": CLIENT_ID,
        },
        "request": {
            "userAttributes": {
                "sub": SUBJECT_ID,
                "custom:tenant_id": "attacker-controlled-tenant",
            },
            "clientMetadata": {"tenant_id": "attacker-controlled-tenant"},
            "scopes": [
                "openid",
                "profile",
                "tinlyt/web.search",
                "tinlyt/web.monitor.delete",
                "other-api/admin",
                "aws.cognito.signin.user.admin",
            ],
        },
        "response": {
            "claimsAndScopeOverrideDetails": {
                "accessTokenGeneration": {
                    "claimsToAddOrOverride": {"existing_claim": "preserved"},
                    "scopesToAdd": ["legacy.scope"],
                    "scopesToSuppress": ["unused.scope"],
                },
                "idTokenGeneration": {"claimsToAddOrOverride": {"display_name": "Existing Value"}},
            }
        },
    }
    for key, value in overrides.items():
        event[key] = value
    return event


def make_handler(
    client: FakeMembershipClient,
) -> CognitoPreTokenGenerationV2Handler:
    resolver = DynamoDBTenantMembershipResolver(
        client,
        table_name=TABLE_NAME,
        user_pool_id=USER_POOL_ID,
    )
    return CognitoPreTokenGenerationV2Handler(
        resolver,
        user_pool_id=USER_POOL_ID,
        allowed_client_ids=frozenset({CLIENT_ID}),
    )


def test_runtime_builder_binds_region_pool_client_allowlist_and_table() -> None:
    client = FakeMembershipClient()
    active_membership(client)
    handler = build_cognito_pretoken_handler(
        {
            "AWS_REGION": "eu-west-1",
            "COGNITO_USER_POOL_ID": USER_POOL_ID,
            "COGNITO_APP_CLIENT_IDS": CLIENT_ID,
            "TENANT_MEMBERSHIP_TABLE": TABLE_NAME,
        },
        client,
    )

    result = handler.handle(make_event())

    claims = result["response"]["claimsAndScopeOverrideDetails"]["accessTokenGeneration"][
        "claimsToAddOrOverride"
    ]
    assert claims["tenant_id"] == "tenant-prod-01"
    assert claims["principal_type"] == "user"


def test_runtime_builder_rejects_region_mismatch_and_duplicate_clients() -> None:
    client = FakeMembershipClient()
    environment = {
        "AWS_REGION": "us-east-1",
        "COGNITO_USER_POOL_ID": USER_POOL_ID,
        "COGNITO_APP_CLIENT_IDS": CLIENT_ID,
        "TENANT_MEMBERSHIP_TABLE": TABLE_NAME,
    }
    with pytest.raises(ValueError, match="region"):
        build_cognito_pretoken_handler(environment, client)

    environment["AWS_REGION"] = "eu-west-1"
    environment["COGNITO_APP_CLIENT_IDS"] = f"{CLIENT_ID},{CLIENT_ID}"
    with pytest.raises(ValueError, match="app client"):
        build_cognito_pretoken_handler(environment, client)


def test_pre_token_v2_uses_authoritative_membership_and_preserves_other_overrides() -> None:
    client = FakeMembershipClient()
    active_membership(client, tenant_id="tinlyt-customer-tenant")
    handler = make_handler(client)
    event = make_event()
    original = copy.deepcopy(event)

    result = handler.handle(event)

    claims = result["response"]["claimsAndScopeOverrideDetails"]["accessTokenGeneration"][
        "claimsToAddOrOverride"
    ]
    assert claims == {
        "existing_claim": "preserved",
        "tenant_id": "tinlyt-customer-tenant",
        "principal_type": "user",
    }
    assert result["response"]["claimsAndScopeOverrideDetails"]["accessTokenGeneration"][
        "scopesToAdd"
    ] == ["tinlyt/web.fetch", "tinlyt/web.search"]
    assert result["response"]["claimsAndScopeOverrideDetails"]["accessTokenGeneration"][
        "scopesToSuppress"
    ] == [
        "aws.cognito.signin.user.admin",
        "other-api/admin",
        "tinlyt/web.monitor.delete",
        "unused.scope",
    ]
    assert result["response"]["claimsAndScopeOverrideDetails"]["idTokenGeneration"][
        "claimsToAddOrOverride"
    ] == {"display_name": "Existing Value"}
    assert event == original
    assert client.calls[0]["ConsistentRead"] is True
    assert client.calls[0]["TableName"] == TABLE_NAME


def test_pre_token_v2_accepts_aws_empty_override_array() -> None:
    client = FakeMembershipClient()
    active_membership(client)
    event = make_event(response={"claimsAndScopeOverrideDetails": []})

    result = make_handler(client).handle(event)

    claims = result["response"]["claimsAndScopeOverrideDetails"]["accessTokenGeneration"][
        "claimsToAddOrOverride"
    ]
    assert claims == {
        "tenant_id": "tenant-prod-01",
        "principal_type": "user",
    }
    assert result["response"]["claimsAndScopeOverrideDetails"]["accessTokenGeneration"][
        "scopesToAdd"
    ] == ["tinlyt/web.fetch", "tinlyt/web.search"]


def test_pre_token_v2_rejects_unapproved_app_client_before_membership_lookup() -> None:
    client = FakeMembershipClient()
    active_membership(client)
    event = make_event(
        callerContext={"clientId": "unapproved-client"},
    )
    with pytest.raises(CognitoTenantMembershipError, match="app client"):
        make_handler(client).handle(event)
    assert client.calls == []


def test_pre_token_v2_rejects_wrong_pool_or_event_version() -> None:
    client = FakeMembershipClient()
    active_membership(client)
    handler = make_handler(client)

    with pytest.raises(CognitoTenantMembershipError, match="user pool"):
        handler.handle(make_event(userPoolId="us-east-1_OtherPool"))
    with pytest.raises(CognitoTenantMembershipError, match="region"):
        handler.handle(make_event(region="us-east-1"))
    with pytest.raises(CognitoTenantMembershipError, match="version"):
        handler.handle(make_event(version="1"))
    with pytest.raises(CognitoTenantMembershipError, match="trigger source"):
        handler.handle(make_event(triggerSource="TokenGeneration_ClientCredentials"))
    with pytest.raises(CognitoTenantMembershipError, match="trigger source"):
        handler.handle(make_event(triggerSource=[]))
    assert client.calls == []


def test_pre_token_v2_rejects_missing_subject_or_membership() -> None:
    client = FakeMembershipClient()
    handler = make_handler(client)
    missing_subject = make_event(
        request={"userAttributes": {}, "clientMetadata": {"tenant_id": "tenant-evil"}}
    )
    with pytest.raises(CognitoTenantMembershipError, match="subject"):
        handler.handle(missing_subject)
    with pytest.raises(CognitoTenantMembershipError, match="active tenant membership"):
        handler.handle(make_event())
    assert len(client.calls) == 1


@pytest.mark.parametrize(
    ("tenant_id", "status", "expected"),
    [
        ("", "active", "tenant identifier"),
        ("bad tenant", "active", "tenant identifier"),
        ("tenant-prod-01", "disabled", "active tenant membership"),
    ],
)
def test_membership_resolver_rejects_invalid_or_inactive_membership(
    tenant_id: str,
    status: str,
    expected: str,
) -> None:
    client = FakeMembershipClient()
    active_membership(client, tenant_id=tenant_id, status=status)
    resolver = DynamoDBTenantMembershipResolver(
        client,
        table_name=TABLE_NAME,
        user_pool_id=USER_POOL_ID,
    )
    with pytest.raises(CognitoTenantMembershipError, match=expected):
        resolver.resolve_active_tenant(USER_POOL_ID, SUBJECT_ID)


def test_membership_resolver_rejects_records_for_different_subjects() -> None:
    client = FakeMembershipClient()
    active_membership(client)
    key = membership_key(USER_POOL_ID, SUBJECT_ID)
    client.items[key]["subject_id"] = "different-subject"
    resolver = DynamoDBTenantMembershipResolver(
        client,
        table_name=TABLE_NAME,
        user_pool_id=USER_POOL_ID,
    )
    with pytest.raises(CognitoTenantMembershipError, match="does not match"):
        resolver.resolve_active_tenant(USER_POOL_ID, SUBJECT_ID)


def test_pre_token_v2_fails_closed_when_membership_store_is_unavailable() -> None:
    client = FakeMembershipClient()
    client.fail_read = True
    with pytest.raises(CognitoTenantMembershipError, match="membership lookup failed"):
        make_handler(client).handle(make_event())


def test_pre_token_v2_rejects_malformed_response_overrides() -> None:
    client = FakeMembershipClient()
    active_membership(client)
    event = make_event(response={"claimsAndScopeOverrideDetails": "malformed"})
    with pytest.raises(CognitoTenantMembershipError, match="response"):
        make_handler(client).handle(event)
