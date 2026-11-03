from __future__ import annotations

import json
import sqlite3
import threading
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from tinlance_agent_platform_api.http import serve
from tinlance_agent_platform_api.service import AgentPlatformAPI, APIRequest, APIResponse
from tinlance_agent_platform_identity import (
    DynamoDBTokenRevocationStore,
    IdentityAuthenticationError,
    JWKSIdentityVerifier,
    JWKSPrincipalResolver,
    SQLiteTokenRevocationStore,
    TokenRevocationChecker,
)

ISSUER = "https://issuer.example.test/"
AUDIENCE = "tinlance-platform"


class StaticKeyProvider:
    def __init__(self, key: Any) -> None:
        self.key = key

    def get_signing_key_from_jwt(self, token: str) -> Any:
        return self.key


class EchoHandler:
    def __init__(self) -> None:
        self.requests: list[APIRequest] = []

    def handle(self, request: APIRequest) -> APIResponse:
        self.requests.append(request)
        return APIResponse(
            "ok",
            {
                "tenant_id": request.tenant_id,
                "subject_id": request.subject_id,
            },
        )


class UnavailableRevocationStore:
    def is_revoked(self, issuer: str, token_id: str) -> bool:
        raise OSError("revocation backend unavailable")


@pytest.fixture
def signing_material() -> tuple[Any, Any]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def make_token(private_key: Any, **overrides: Any) -> str:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "iss": ISSUER,
        "sub": "subject-a",
        "aud": AUDIENCE,
        "jti": "jti-a",
        "client_id": "tinlance-test-client",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "tenant_id": "tenant-a",
        "principal_type": "user",
        "roles": ["operator"],
        "scope": "agent:run evidence:read",
    }
    claims.update(overrides)
    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"typ": "at+jwt", "kid": "key-1"},
    )


def resolver_for(
    public_key: Any,
    revocations: TokenRevocationChecker,
) -> JWKSPrincipalResolver:
    verifier = JWKSIdentityVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url="https://issuer.example.test/.well-known/jwks.json",
        key_provider=StaticKeyProvider(public_key),
    )
    return JWKSPrincipalResolver(verifier, revocations)


def send_request(
    endpoint: str,
    token: str,
    *,
    tenant_id: str = "tenant-a",
    subject_id: str = "subject-a",
) -> tuple[int, dict[str, object]]:
    body = json.dumps(
        {
            "tenant_id": tenant_id,
            "subject_id": subject_id,
            "operation": "test.echo",
            "payload": {},
        }
    ).encode()
    request = urllib.request.Request(
        endpoint,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-Tinlance-API-Version": "1.1",
            "X-Request-ID": "request-identity-001",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def with_server(
    resolver: JWKSPrincipalResolver,
    *,
    session_revoker: JWKSPrincipalResolver | None = None,
):
    handler = EchoHandler()
    server = serve(
        AgentPlatformAPI(handler),
        resolver,
        host="127.0.0.1",
        port=0,
        session_revoker=session_revoker,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_address[1]}/v1/agent-platform"
    return handler, server, thread, endpoint


def send_revoke_request(endpoint: str, token: str) -> tuple[int, dict[str, object]]:
    revoke_endpoint = endpoint.rsplit("/", 1)[0] + "/session/revoke"
    request = urllib.request.Request(
        revoke_endpoint,
        data=b"{}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-Tinlance-API-Version": "1.1",
            "X-Request-ID": "request-session-revoke-001",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def test_resolver_maps_verified_identity_to_platform_principal(
    signing_material: tuple[Any, Any], tmp_path: Path
) -> None:
    private_key, public_key = signing_material
    revocations = SQLiteTokenRevocationStore(tmp_path / "revocations.db")
    resolver = resolver_for(public_key, revocations)
    principal = resolver.resolve(make_token(private_key))
    assert principal.subject_id == "subject-a"
    assert principal.tenant_id == "tenant-a"
    assert principal.principal_type == "user"
    assert principal.roles == frozenset({"operator"})
    assert principal.scopes == frozenset({"agent:run", "evidence:read"})


def test_http_boundary_binds_request_tenant_to_verified_identity(
    signing_material: tuple[Any, Any], tmp_path: Path
) -> None:
    private_key, public_key = signing_material
    resolver = resolver_for(public_key, SQLiteTokenRevocationStore(tmp_path / "revocations.db"))
    handler, server, thread, endpoint = with_server(resolver)
    try:
        status, body = send_request(endpoint, make_token(private_key))
        assert status == 200
        assert body["payload"] == {"tenant_id": "tenant-a", "subject_id": "subject-a"}
        assert len(handler.requests) == 1

        status, body = send_request(endpoint, make_token(private_key), tenant_id="tenant-victim")
        assert status == 403
        assert body["error"] == "forbidden"
        assert len(handler.requests) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_revoked_tokens_are_rejected_and_store_survives_restart(
    signing_material: tuple[Any, Any], tmp_path: Path
) -> None:
    private_key, public_key = signing_material
    path = tmp_path / "revocations.db"
    first_store = SQLiteTokenRevocationStore(path)
    assert first_store.revoke(ISSUER, "jti-a", reason="security incident")
    assert not first_store.revoke(ISSUER, "jti-a", reason="duplicate")
    second_store = SQLiteTokenRevocationStore(path)
    assert second_store.is_revoked(ISSUER, "jti-a")
    assert not second_store.is_revoked("https://other-issuer.example/", "jti-a")

    resolver = resolver_for(public_key, second_store)
    handler, server, thread, endpoint = with_server(resolver)
    try:
        status, body = send_request(endpoint, make_token(private_key))
        assert status == 401
        assert body["error"] == "unauthorized"
        assert handler.requests == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_revocation_backend_failure_fails_closed(
    signing_material: tuple[Any, Any], tmp_path: Path
) -> None:
    private_key, public_key = signing_material
    resolver = resolver_for(public_key, UnavailableRevocationStore())
    handler, server, thread, endpoint = with_server(resolver)
    try:
        status, body = send_request(endpoint, make_token(private_key))
        assert status == 401
        assert body["error"] == "unauthorized"
        assert handler.requests == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_identity_resolver_rejects_invalid_signature(
    signing_material: tuple[Any, Any], tmp_path: Path
) -> None:
    _, public_key = signing_material
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    resolver = resolver_for(public_key, SQLiteTokenRevocationStore(tmp_path / "revocations.db"))
    with pytest.raises(IdentityAuthenticationError):
        resolver.resolve(make_token(attacker_key))


def test_cognito_origin_jti_revokes_every_access_token_in_the_session_family(
    signing_material: tuple[Any, Any], tmp_path: Path
) -> None:
    private_key, public_key = signing_material
    path = tmp_path / "revocations.db"
    store = SQLiteTokenRevocationStore(path)
    assert store.revoke(ISSUER, "origin-jti-a", reason="user signed out")
    resolver = resolver_for(public_key, store)
    with pytest.raises(IdentityAuthenticationError, match="revoked"):
        resolver.resolve(make_token(private_key, origin_jti="origin-jti-a"))


def test_revoke_identity_persists_both_access_token_and_session_family_ids(
    signing_material: tuple[Any, Any], tmp_path: Path
) -> None:
    private_key, public_key = signing_material
    store = SQLiteTokenRevocationStore(tmp_path / "revocations.db")
    verifier = JWKSIdentityVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url="https://issuer.example.test/.well-known/jwks.json",
        key_provider=StaticKeyProvider(public_key),
    )
    identity = verifier.verify(make_token(private_key, origin_jti="origin-jti-a"))
    store.revoke_identity(identity, reason="user signed out")
    assert store.is_revoked(ISSUER, "jti-a")
    assert store.is_revoked(ISSUER, "origin-jti-a")


def test_session_revoke_endpoint_revokes_access_token_and_family_atomically(
    signing_material: tuple[Any, Any], tmp_path: Path
) -> None:
    private_key, public_key = signing_material
    path = tmp_path / "revocations.db"
    store = SQLiteTokenRevocationStore(path)
    resolver = resolver_for(public_key, store)
    handler, server, thread, endpoint = with_server(resolver, session_revoker=resolver)
    token = make_token(private_key, origin_jti="origin-jti-a")
    try:
        status, body = send_revoke_request(endpoint, token)
        assert status == 200
        assert body == {"status": "revoked"}
        assert store.is_revoked(ISSUER, "jti-a")
        assert store.is_revoked(ISSUER, "origin-jti-a")
        with sqlite3.connect(path) as connection:
            request_ids = connection.execute(
                "SELECT DISTINCT request_id FROM revoked_tokens"
            ).fetchall()
        assert request_ids == [("request-session-revoke-001",)]

        status, body = send_request(endpoint, token)
        assert status == 401
        assert body["error"] == "unauthorized"
        assert handler.requests == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_session_revoke_endpoint_fails_closed_without_a_revocation_writer(
    signing_material: tuple[Any, Any], tmp_path: Path
) -> None:
    private_key, public_key = signing_material
    resolver = resolver_for(public_key, UnavailableRevocationStore())
    handler, server, thread, endpoint = with_server(resolver, session_revoker=resolver)
    try:
        status, body = send_revoke_request(endpoint, make_token(private_key))
        assert status == 503
        assert body["error"] == "session_revocation_unavailable"
        assert handler.requests == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_session_revoke_endpoint_rejects_invalid_identity(
    signing_material: tuple[Any, Any], tmp_path: Path
) -> None:
    _, public_key = signing_material
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    resolver = resolver_for(public_key, SQLiteTokenRevocationStore(tmp_path / "revocations.db"))
    handler, server, thread, endpoint = with_server(resolver, session_revoker=resolver)
    try:
        status, body = send_revoke_request(endpoint, make_token(attacker_key))
        assert status == 401
        assert body["error"] == "unauthorized"
        assert handler.requests == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_revocation_store_adds_request_id_column_to_existing_schema(tmp_path: Path) -> None:
    path = tmp_path / "legacy-revocations.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE revoked_tokens (
                issuer TEXT NOT NULL,
                token_id TEXT NOT NULL,
                revoked_at TEXT NOT NULL,
                reason TEXT NOT NULL,
                PRIMARY KEY (issuer, token_id)
            )
            """
        )
    SQLiteTokenRevocationStore(path)
    with sqlite3.connect(path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(revoked_tokens)")}
    assert "request_id" in columns


class FakeDynamoDBClient:
    def __init__(self) -> None:
        self.items: dict[str, dict[str, object]] = {}
        self.transactions: list[list[dict[str, object]]] = []
        self.fail_transaction = False
        self.fail_read = False
        self.last_read_consistent: bool | None = None

    def transact_write_items(self, **kwargs: Any) -> dict[str, object]:
        if self.fail_transaction:
            raise OSError("DynamoDB transaction unavailable")
        actions = kwargs["TransactItems"]
        pending = dict(self.items)
        for action in actions:
            put = action["Put"]
            item = put["Item"]
            pending[str(item["revocation_key"])] = dict(item)
        self.items = pending
        self.transactions.append(list(actions))
        return {}

    def get_item(self, **kwargs: Any) -> dict[str, object]:
        if self.fail_read:
            raise OSError("DynamoDB read unavailable")
        self.last_read_consistent = kwargs["ConsistentRead"]
        key = kwargs["Key"]["revocation_key"]
        item = self.items.get(str(key))
        return {"Item": dict(item)} if item is not None else {}


def test_dynamodb_revocation_store_atomically_writes_token_and_family_ids(
    signing_material: tuple[Any, Any],
) -> None:
    private_key, public_key = signing_material
    verifier = JWKSIdentityVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url="https://issuer.example.test/.well-known/jwks.json",
        key_provider=StaticKeyProvider(public_key),
    )
    identity = verifier.verify(make_token(private_key, origin_jti="origin-jti-dynamodb"))
    client = FakeDynamoDBClient()
    store = DynamoDBTokenRevocationStore(
        client,
        table_name="tinlyt-token-revocations",
        token_retention_seconds=600,
        family_retention_seconds=31 * 24 * 60 * 60,
    )

    identifiers = store.revoke_identity(
        identity,
        reason="user signed out",
        request_id="request-dynamodb-revoke-001",
    )

    assert identifiers == ("jti-a", "origin-jti-dynamodb")
    assert len(client.transactions) == 1
    assert len(client.transactions[0]) == 2
    assert store.is_revoked(ISSUER, "jti-a")
    assert store.is_revoked(ISSUER, "origin-jti-dynamodb")
    assert client.last_read_consistent is True
    token_item = next(item for item in client.items.values() if item["token_id"] == "jti-a")
    family_item = next(
        item for item in client.items.values() if item["token_id"] == "origin-jti-dynamodb"
    )
    assert token_item["request_id"] == "request-dynamodb-revoke-001"
    assert family_item["request_id"] == "request-dynamodb-revoke-001"
    assert int(family_item["expires_at"]) > int(token_item["expires_at"])


def test_dynamodb_revocation_store_expired_ttl_records_are_not_active() -> None:
    client = FakeDynamoDBClient()
    store = DynamoDBTokenRevocationStore(client, table_name="tinlyt-token-revocations")
    key = store._revocation_key(ISSUER, "expired-jti")
    client.items[key] = {
        "revocation_key": key,
        "issuer": ISSUER,
        "token_id": "expired-jti",
        "expires_at": 1,
    }
    assert not store.is_revoked(ISSUER, "expired-jti")


def test_dynamodb_revocation_store_fails_closed_on_read_or_transaction_errors(
    signing_material: tuple[Any, Any],
) -> None:
    private_key, public_key = signing_material
    verifier = JWKSIdentityVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url="https://issuer.example.test/.well-known/jwks.json",
        key_provider=StaticKeyProvider(public_key),
    )
    identity = verifier.verify(make_token(private_key, origin_jti="origin-jti-dynamodb"))
    client = FakeDynamoDBClient()
    store = DynamoDBTokenRevocationStore(client, table_name="tinlyt-token-revocations")

    client.fail_transaction = True
    with pytest.raises(OSError, match="transaction unavailable"):
        store.revoke_identity(identity, reason="user signed out")
    assert client.items == {}

    client.fail_transaction = False
    store.revoke_identity(identity, reason="user signed out")
    client.fail_read = True
    with pytest.raises(OSError, match="read unavailable"):
        store.is_revoked(ISSUER, "jti-a")


def test_dynamodb_revocation_store_rejects_invalid_configuration() -> None:
    client = FakeDynamoDBClient()
    with pytest.raises(ValueError, match="table"):
        DynamoDBTokenRevocationStore(client, table_name=" ")
    with pytest.raises(ValueError, match="retention"):
        DynamoDBTokenRevocationStore(
            client,
            table_name="tinlyt-token-revocations",
            token_retention_seconds=600,
            family_retention_seconds=60,
        )
