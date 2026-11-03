"""Cognito V2 Pre Token Generation tenant membership claims."""

from __future__ import annotations

import copy
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol


class CognitoTenantMembershipError(PermissionError):
    """Raised when a Cognito user cannot be bound to a trusted tenant."""


class DynamoDBMembershipClient(Protocol):
    def get_item(self, **kwargs: Any) -> Mapping[str, object]: ...


class TenantMembershipResolver(Protocol):
    def resolve_active_tenant(self, user_pool_id: str, subject_id: str) -> str: ...


_USER_POOL_ID = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]+_[A-Za-z0-9]+$")
_SUBJECT_ID = re.compile(r"^[A-Za-z0-9-]{1,128}$")
_TENANT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_CLIENT_ID = re.compile(r"^[A-Za-z0-9]{1,128}$")
_TABLE_NAME = re.compile(r"^[A-Za-z0-9_.-]{3,255}$")
_ALLOWED_USER_TRIGGER_SOURCES = frozenset(
    {
        "TokenGeneration_HostedAuth",
        "TokenGeneration_Authentication",
        "TokenGeneration_NewPasswordChallenge",
        "TokenGeneration_AuthenticateDevice",
        "TokenGeneration_RefreshTokens",
    }
)


@dataclass(frozen=True, slots=True)
class DynamoDBTenantMembershipResolver:
    """Resolve one active tenant from an authoritative, strongly-read membership row.

    The table uses a string partition key named subject_key. The key is a
    SHA-256 digest of the user-pool ID and Cognito subject, so different pools
    cannot collide and raw subject identifiers are not used as partition keys.
    """

    client: DynamoDBMembershipClient
    table_name: str
    user_pool_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.table_name, str) or not _TABLE_NAME.fullmatch(self.table_name):
            raise ValueError("Cognito membership table name is invalid")
        if not isinstance(self.user_pool_id, str) or not _USER_POOL_ID.fullmatch(self.user_pool_id):
            raise ValueError("Cognito membership user pool ID is invalid")

    @staticmethod
    def subject_key(user_pool_id: str, subject_id: str) -> str:
        return hashlib.sha256(f"{user_pool_id}\0{subject_id}".encode()).hexdigest()

    def resolve_active_tenant(self, user_pool_id: str, subject_id: str) -> str:
        if user_pool_id != self.user_pool_id:
            raise CognitoTenantMembershipError("Cognito membership user pool is not trusted")
        if not isinstance(subject_id, str) or not _SUBJECT_ID.fullmatch(subject_id):
            raise CognitoTenantMembershipError("Cognito subject identifier is invalid")

        key = self.subject_key(user_pool_id, subject_id)
        response = self.client.get_item(
            TableName=self.table_name,
            Key={"subject_key": key},
            ConsistentRead=True,
        )
        item = response.get("Item")
        if item is None:
            raise CognitoTenantMembershipError("user has no active tenant membership")
        if not isinstance(item, Mapping) or (
            item.get("subject_key") != key
            or item.get("user_pool_id") != user_pool_id
            or item.get("subject_id") != subject_id
        ):
            raise CognitoTenantMembershipError("tenant membership record does not match the user")
        if item.get("status") != "active":
            raise CognitoTenantMembershipError("user has no active tenant membership")
        tenant_id = item.get("tenant_id")
        if not isinstance(tenant_id, str) or not _TENANT_ID.fullmatch(tenant_id):
            raise CognitoTenantMembershipError("tenant identifier in membership record is invalid")
        return tenant_id


@dataclass(frozen=True, slots=True)
class CognitoPreTokenGenerationV2Handler:
    """Add only server-derived tenant and principal claims to Cognito access tokens."""

    membership_resolver: TenantMembershipResolver
    user_pool_id: str
    allowed_client_ids: frozenset[str]

    def __post_init__(self) -> None:
        if not isinstance(self.user_pool_id, str) or not _USER_POOL_ID.fullmatch(self.user_pool_id):
            raise ValueError("Cognito Pre Token Generation user pool ID is invalid")
        if (
            not isinstance(self.allowed_client_ids, frozenset)
            or not self.allowed_client_ids
            or any(
                not isinstance(client_id, str)
                or not _CLIENT_ID.fullmatch(client_id)
                for client_id in self.allowed_client_ids
            )
        ):
            raise ValueError("Cognito Pre Token Generation app-client allowlist is invalid")

    def handle(self, event: Mapping[str, object]) -> dict[str, object]:
        if not isinstance(event, Mapping):
            raise CognitoTenantMembershipError("Cognito trigger event must be an object")
        result = copy.deepcopy(dict(event))
        if result.get("version") != "2":
            raise CognitoTenantMembershipError(
                "Cognito Pre Token Generation event version must be 2"
            )
        trigger_source = result.get("triggerSource")
        if (
            not isinstance(trigger_source, str)
            or trigger_source not in _ALLOWED_USER_TRIGGER_SOURCES
        ):
            raise CognitoTenantMembershipError(
                "Cognito trigger source is not a supported human-user flow"
            )
        if result.get("userPoolId") != self.user_pool_id:
            raise CognitoTenantMembershipError("Cognito trigger user pool is not trusted")
        expected_region = self.user_pool_id.split("_", 1)[0]
        if result.get("region") != expected_region:
            raise CognitoTenantMembershipError(
                "Cognito trigger region does not match the user pool"
            )

        caller_context = result.get("callerContext")
        if not isinstance(caller_context, Mapping):
            raise CognitoTenantMembershipError("Cognito caller context is missing")
        client_id = caller_context.get("clientId")
        if not isinstance(client_id, str) or client_id not in self.allowed_client_ids:
            raise CognitoTenantMembershipError("Cognito app client is not trusted")

        request = result.get("request")
        if not isinstance(request, Mapping):
            raise CognitoTenantMembershipError("Cognito trigger request is missing")
        user_attributes = request.get("userAttributes")
        if not isinstance(user_attributes, Mapping):
            raise CognitoTenantMembershipError("Cognito user attributes are missing")
        subject_id = user_attributes.get("sub")
        if not isinstance(subject_id, str) or not subject_id:
            raise CognitoTenantMembershipError("Cognito subject is missing")

        try:
            tenant_id = self.membership_resolver.resolve_active_tenant(
                self.user_pool_id,
                subject_id,
            )
        except CognitoTenantMembershipError:
            raise
        except Exception as exc:
            raise CognitoTenantMembershipError("trusted tenant membership lookup failed") from exc
        if not isinstance(tenant_id, str) or not _TENANT_ID.fullmatch(tenant_id):
            raise CognitoTenantMembershipError(
                "trusted tenant membership returned an invalid tenant ID"
            )

        response_value = result.get("response")
        if response_value is None:
            response: dict[str, object] = {}
        elif isinstance(response_value, Mapping):
            response = dict(response_value)
        else:
            raise CognitoTenantMembershipError("Cognito trigger response is malformed")

        details_value = response.get("claimsAndScopeOverrideDetails")
        if details_value is None or details_value == []:
            details: dict[str, object] = {}
        elif isinstance(details_value, Mapping):
            details = dict(details_value)
        else:
            raise CognitoTenantMembershipError(
                "Cognito claims-and-scope override response is malformed"
            )

        access_value = details.get("accessTokenGeneration")
        if access_value is None:
            access: dict[str, object] = {}
        elif isinstance(access_value, Mapping):
            access = dict(access_value)
        else:
            raise CognitoTenantMembershipError(
                "Cognito access-token override response is malformed"
            )

        claims_value = access.get("claimsToAddOrOverride")
        if claims_value is None:
            claims: dict[str, object] = {}
        elif isinstance(claims_value, Mapping):
            claims = dict(claims_value)
        else:
            raise CognitoTenantMembershipError("Cognito access-token claims override is malformed")

        claims["tenant_id"] = tenant_id
        claims["principal_type"] = "user"
        access["claimsToAddOrOverride"] = claims
        details["accessTokenGeneration"] = access
        response["claimsAndScopeOverrideDetails"] = details
        result["response"] = response
        return result



def build_cognito_pretoken_handler(
    environment: Mapping[str, str],
    dynamodb_client: DynamoDBMembershipClient,
) -> CognitoPreTokenGenerationV2Handler:
    """Build the V2 trigger from explicit environment configuration and an SDK client."""

    required = (
        "AWS_REGION",
        "COGNITO_USER_POOL_ID",
        "COGNITO_APP_CLIENT_IDS",
        "TENANT_MEMBERSHIP_TABLE",
    )
    values = {name: environment.get(name) for name in required}
    if any(not isinstance(value, str) or not value for value in values.values()):
        raise ValueError("Cognito Pre Token Generation environment configuration is incomplete")

    region = values["AWS_REGION"]
    user_pool_id = values["COGNITO_USER_POOL_ID"]
    raw_client_ids = values["COGNITO_APP_CLIENT_IDS"]
    table_name = values["TENANT_MEMBERSHIP_TABLE"]
    assert isinstance(region, str)
    assert isinstance(user_pool_id, str)
    assert isinstance(raw_client_ids, str)
    assert isinstance(table_name, str)

    if user_pool_id.split("_", 1)[0] != region:
        raise ValueError("Cognito user pool region does not match AWS_REGION")
    client_ids = tuple(raw_client_ids.split(","))
    if (
        not client_ids
        or any(not client_id or client_id != client_id.strip() for client_id in client_ids)
        or len(set(client_ids)) != len(client_ids)
    ):
        raise ValueError("Cognito app client configuration is invalid")

    resolver = DynamoDBTenantMembershipResolver(
        dynamodb_client,
        table_name=table_name,
        user_pool_id=user_pool_id,
    )
    return CognitoPreTokenGenerationV2Handler(
        resolver,
        user_pool_id=user_pool_id,
        allowed_client_ids=frozenset(client_ids),
    )
