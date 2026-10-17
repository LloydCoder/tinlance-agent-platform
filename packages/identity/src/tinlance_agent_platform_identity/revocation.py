"""Token revocation contracts and a durable local reference store.

Production deployments should inject a shared, highly available revocation
adapter. The SQLite implementation is durable across process restarts on one
host; it is not a substitute for a multi-instance production revocation service.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol


class TokenRevocationChecker(Protocol):
    def is_revoked(self, issuer: str, token_id: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class SQLiteTokenRevocationStore:
    path: Path

    def __post_init__(self) -> None:
        if str(self.path) == ":memory:" or not str(self.path).strip():
            raise ValueError("revocation store requires a persistent filesystem path")
        with self._connect() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS revoked_tokens (
                    issuer TEXT NOT NULL,
                    token_id TEXT NOT NULL,
                    revoked_at TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    PRIMARY KEY (issuer, token_id)
                )
                """
            )

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
        with self._connect() as db:
            cursor = db.execute(
                """
                INSERT INTO revoked_tokens (issuer, token_id, revoked_at, reason)
                VALUES (?, ?, ?, ?)
                ON CONFLICT (issuer, token_id) DO NOTHING
                """,
                (issuer, token_id, timestamp.astimezone(UTC).isoformat(), reason),
            )
            return cursor.rowcount == 1

    def is_revoked(self, issuer: str, token_id: str) -> bool:
        self._validate_identity(issuer, token_id)
        with self._connect() as db:
            row = db.execute(
                "SELECT 1 FROM revoked_tokens WHERE issuer = ? AND token_id = ?",
                (issuer, token_id),
            ).fetchone()
        return row is not None
