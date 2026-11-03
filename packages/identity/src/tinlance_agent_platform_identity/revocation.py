"""Token revocation contracts and a durable local reference store.

Production deployments should inject a shared, highly available revocation
adapter. The SQLite implementation is durable across process restarts on one
host; it is not a substitute for a multi-instance production revocation service.
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Protocol

from .federation import VerifiedAgentIdentity


class TokenRevocationChecker(Protocol):
    def is_revoked(self, issuer: str, token_id: str) -> bool: ...


class DynamoDBClient(Protocol):
    """Subset of a boto3 DynamoDB resource client's auto-marshalling API."""

    def get_item(self, **kwargs: Any) -> Mapping[str, object]: ...

    def transact_write_items(self, **kwargs: Any) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class SQLiteTokenRevocationStore:
    path: Path

    def __post_init__(self) -> None:
        if str(self.path) == ":memory:" or not str(self.path).strip():
            raise ValueError("revocation store requires a persistent filesystem path")
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS revoked_tokens (
                    issuer TEXT NOT NULL,
                    token_id TEXT NOT NULL,
                    revoked_at TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    request_id TEXT,
                    PRIMARY KEY (issuer, token_id)
                )
                """
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(revoked_tokens)")}
            if "request_id" not in columns:
                connection.execute("ALTER TABLE revoked_tokens ADD COLUMN request_id TEXT")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=5.0)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _validate_identity(issuer: str, token_id: str) -> None:
        if (
            not issuer
            or issuer != issuer.strip()
            or not issuer.startswith("https://")
            or not token_id
            or token_id != token_id.strip()
        ):
            raise ValueError("revocation identity must contain normalized issuer and token ID")

    def revoke(
        self,
        issuer: str,
        token_id: str,
        *,
        reason: str,
        revoked_at: datetime | None = None,
    ) -> bool:
        self._validate_identity(issuer, token_id)
        if not reason or reason != reason.strip():
            raise ValueError("revocation reason must be normalized and non-empty")
        timestamp = revoked_at or datetime.now(UTC)
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("revocation timestamp must be timezone-aware")
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """
                INSERT INTO revoked_tokens (issuer, token_id, revoked_at, reason)
                VALUES (?, ?, ?, ?)
                ON CONFLICT (issuer, token_id) DO NOTHING
                """,
                (issuer, token_id, timestamp.astimezone(UTC).isoformat(), reason),
            )
            return cursor.rowcount == 1

    def revoke_identity(
        self,
        identity: VerifiedAgentIdentity,
        *,
        reason: str,
        revoked_at: datetime | None = None,
        request_id: str | None = None,
    ) -> tuple[str, ...]:
        """Atomically revoke one JWT and every configured token-family identifier."""

        identifiers = tuple(sorted({identity.token_id, *identity.revocation_ids}))
        for identifier in identifiers:
            self._validate_identity(identity.issuer, identifier)
        if not reason or reason != reason.strip():
            raise ValueError("revocation reason must be normalized and non-empty")
        if request_id is not None and (
            not request_id
            or request_id != request_id.strip()
            or len(request_id) > 256
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in request_id)
        ):
            raise ValueError("revocation request ID must be normalized when provided")
        timestamp = revoked_at or datetime.now(UTC)
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("revocation timestamp must be timezone-aware")
        revoked_at_value = timestamp.astimezone(UTC).isoformat()
        with closing(self._connect()) as connection, connection:
            connection.executemany(
                """
                INSERT INTO revoked_tokens (issuer, token_id, revoked_at, reason, request_id)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (issuer, token_id) DO NOTHING
                """,
                [
                    (identity.issuer, identifier, revoked_at_value, reason, request_id)
                    for identifier in identifiers
                ],
            )
        return identifiers

    def is_revoked(self, issuer: str, token_id: str) -> bool:
        self._validate_identity(issuer, token_id)
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT 1 FROM revoked_tokens WHERE issuer = ? AND token_id = ?",
                (issuer, token_id),
            ).fetchone()
        return row is not None


@dataclass(frozen=True, slots=True)
class DynamoDBTokenRevocationStore:
    """Shared, atomic token-family revocation backed by a DynamoDB table.

    Pass the auto-marshalling client from boto3.resource("dynamodb").meta.client.
    The table must use a string partition key named revocation_key and have TTL
    enabled on the numeric expires_at attribute.
    """

    client: DynamoDBClient
    table_name: str
    token_retention_seconds: int = 600
    family_retention_seconds: int = 31 * 24 * 60 * 60

    def __post_init__(self) -> None:
        if (
            not isinstance(self.table_name, str)
            or not self.table_name
            or self.table_name != self.table_name.strip()
        ):
            raise ValueError("DynamoDB revocation table name must be normalized and non-empty")
        if (
            isinstance(self.token_retention_seconds, bool)
            or not isinstance(self.token_retention_seconds, int)
            or self.token_retention_seconds <= 0
            or isinstance(self.family_retention_seconds, bool)
            or not isinstance(self.family_retention_seconds, int)
            or self.family_retention_seconds < self.token_retention_seconds
        ):
            raise ValueError("DynamoDB revocation retention periods are invalid")

    @staticmethod
    def _revocation_key(issuer: str, token_id: str) -> str:
        value = f"{issuer}\0{token_id}".encode()
        return hashlib.sha256(value).hexdigest()

    @staticmethod
    def _validate_identity(issuer: str, token_id: str) -> None:
        if (
            not isinstance(issuer, str)
            or not issuer
            or issuer != issuer.strip()
            or not issuer.startswith("https://")
            or not isinstance(token_id, str)
            or not token_id
            or token_id != token_id.strip()
            or any(ord(character) < 0x21 or ord(character) == 0x7F for character in token_id)
        ):
            raise ValueError("revocation identity must contain normalized issuer and token ID")

    def revoke_identity(
        self,
        identity: VerifiedAgentIdentity,
        *,
        reason: str,
        revoked_at: datetime | None = None,
        request_id: str | None = None,
    ) -> tuple[str, ...]:
        """Atomically revoke one access token and all configured family IDs."""

        identifiers = tuple(sorted({identity.token_id, *identity.revocation_ids}))
        if not identifiers or len(identifiers) > 100:
            raise ValueError("DynamoDB revocation transaction must contain 1 to 100 identifiers")
        for identifier in identifiers:
            self._validate_identity(identity.issuer, identifier)
        if not isinstance(reason, str) or not reason or reason != reason.strip():
            raise ValueError("revocation reason must be normalized and non-empty")
        if request_id is not None and (
            not isinstance(request_id, str)
            or not request_id
            or request_id != request_id.strip()
            or len(request_id) > 256
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in request_id)
        ):
            raise ValueError("revocation request ID must be normalized when provided")
        timestamp = revoked_at or datetime.now(UTC)
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("revocation timestamp must be timezone-aware")
        if (
            identity.expires_at.tzinfo is None
            or identity.expires_at.utcoffset() is None
            or identity.expires_at <= timestamp
        ):
            raise ValueError("identity expiry must be timezone-aware and after revocation time")

        revoked_at_epoch = int(timestamp.astimezone(UTC).timestamp())
        token_expires_at = int(identity.expires_at.timestamp()) + self.token_retention_seconds
        family_expires_at = revoked_at_epoch + self.family_retention_seconds
        actions: list[dict[str, Any]] = []
        for identifier in identifiers:
            expires_at = (
                token_expires_at if identifier == identity.token_id else family_expires_at
            )
            item: dict[str, Any] = {
                "revocation_key": self._revocation_key(identity.issuer, identifier),
                "issuer": identity.issuer,
                "token_id": identifier,
                "revoked_at": timestamp.astimezone(UTC).isoformat(),
                "reason": reason,
                "expires_at": expires_at,
            }
            if request_id is not None:
                item["request_id"] = request_id
            actions.append({"Put": {"TableName": self.table_name, "Item": item}})

        self.client.transact_write_items(TransactItems=actions)
        return identifiers

    def is_revoked(self, issuer: str, token_id: str) -> bool:
        """Read revocation state consistently; malformed records fail closed."""

        self._validate_identity(issuer, token_id)
        response = self.client.get_item(
            TableName=self.table_name,
            Key={"revocation_key": self._revocation_key(issuer, token_id)},
            ConsistentRead=True,
        )
        item = response.get("Item")
        if item is None:
            return False
        if not isinstance(item, Mapping) or (
            item.get("issuer") != issuer or item.get("token_id") != token_id
        ):
            raise RuntimeError("DynamoDB revocation record does not match its lookup key")
        expires_at = item.get("expires_at")
        if isinstance(expires_at, bool) or not isinstance(expires_at, (int, float, Decimal)):
            raise RuntimeError("DynamoDB revocation record has an invalid TTL")
        return int(expires_at) > int(time.time())
