"""Durable SQLite outbox/inbox reference adapters.

Delivery is at-least-once. The outbox preserves committed event intent; the inbox
provides durable consumer deduplication. Neither claims exactly-once external effects.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Callable
from uuid import uuid4

MAX_EVENT_BYTES = 1_048_576


class EventDeliveryConflictError(ValueError):
    """A replay reused an event/idempotency identity with different content."""


@dataclass(frozen=True, slots=True)
class SQLiteOutboxRecord:
    event_id: str
    source: str
    tenant_id: str
    aggregate_id: str
    event_type: str
    payload: bytes
    payload_digest: str
    idempotency_key: str
    created_at: datetime
    attempts: int
    max_attempts: int
    next_attempt_at: datetime
    published_at: datetime | None
    lease_id: str | None
    lease_owner: str | None
    lease_expires_at: datetime | None
    dead_lettered_at: datetime | None
    replay_count: int
    last_error: str | None


def _normalized(value: str, name: str, maximum: int = 256) -> None:
    if not value or value != value.strip() or len(value) > maximum:
        raise ValueError(f"{name} must be normalized and within its size limit")


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value is not None else None


def _validate_envelope(
    *,
    tenant_id: str,
    source: str,
    event_type: str,
    payload: bytes,
    event_id: str | None,
) -> tuple[str, str, bytes, str]:
    _normalized(tenant_id, "tenant_id")
    _normalized(source, "source", 2048)
    _normalized(event_type, "event_type")
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_EVENT_BYTES:
        raise ValueError("event payload must be non-empty bytes no larger than 1 MiB")
    try:
        decoded = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("event payload must be valid JSON") from exc
    if not isinstance(decoded, dict):
        raise ValueError("event payload must be a JSON object")
    for key in (
        "specversion", "id", "source", "type", "time", "subject", "datacontenttype",
        "tenantid", "executionid", "traceid", "correlationid", "data",
    ):
        if key not in decoded:
            raise ValueError(f"event payload is missing canonical attribute {key}")
    if decoded["specversion"] != "1.0" or decoded["datacontenttype"] != "application/json":
        raise ValueError("event payload must use the canonical CloudEvents-compatible envelope")
    if decoded["tenantid"] != tenant_id or decoded["source"] != source or decoded["type"] != event_type:
        raise ValueError("outbox scope does not match canonical envelope attributes")
    if not isinstance(decoded["id"], str) or not decoded["id"].strip():
        raise ValueError("canonical event id is required")
    if event_id is not None and decoded["id"] != event_id:
        raise ValueError("event_id does not match canonical envelope id")
    if not isinstance(decoded["data"], dict):
        raise ValueError("canonical event data must be an object")
    resolved_id = decoded["id"]
    canonical = json.dumps(decoded, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    return resolved_id, hashlib.sha256(canonical).hexdigest(), canonical, str(decoded["type"])


class SQLiteTransactionalOutbox:
    """Durable outbox with owner-bound expiring leases and bounded retry/replay."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_attempts: int = 5,
        base_delay_seconds: float = 1.0,
        max_delay_seconds: float = 60.0,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not str(path).strip():
            raise ValueError("outbox database path is required")
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        if base_delay_seconds < 0 or max_delay_seconds < 0 or base_delay_seconds > max_delay_seconds:
            raise ValueError("retry delays must be non-negative and ordered")
        self.path = str(path)
        self.max_attempts = max_attempts
        self.base_delay_seconds = base_delay_seconds
        self.max_delay_seconds = max_delay_seconds
        self._clock = clock or (lambda: datetime.now(UTC))
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10.0)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=10000")
        return db

    def _ensure_schema(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS platform_event_outbox (
                    event_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    aggregate_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    payload_digest TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL,
                    next_attempt_at TEXT NOT NULL,
                    published_at TEXT,
                    lease_id TEXT,
                    lease_owner TEXT,
                    lease_expires_at TEXT,
                    dead_lettered_at TEXT,
                    replay_count INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    PRIMARY KEY (source, event_id),
                    UNIQUE (tenant_id, idempotency_key)
                );
                CREATE INDEX IF NOT EXISTS idx_platform_outbox_ready
                    ON platform_event_outbox (tenant_id, published_at, dead_lettered_at, next_attempt_at);
                CREATE TABLE IF NOT EXISTS platform_outbox_replay_log (
                    replay_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    replayed_at TEXT NOT NULL
                );
                """
            )

    @staticmethod
    def _decode(row: sqlite3.Row) -> SQLiteOutboxRecord:
        return SQLiteOutboxRecord(
            event_id=row["event_id"],
            source=row["source"],
            tenant_id=row["tenant_id"],
            aggregate_id=row["aggregate_id"],
            event_type=row["event_type"],
            payload=bytes(row["payload"]),
            payload_digest=row["payload_digest"],
            idempotency_key=row["idempotency_key"],
            created_at=datetime.fromisoformat(row["created_at"]),
            attempts=int(row["attempts"]),
            max_attempts=int(row["max_attempts"]),
            next_attempt_at=datetime.fromisoformat(row["next_attempt_at"]),
            published_at=_dt(row["published_at"]),
            lease_id=row["lease_id"],
            lease_owner=row["lease_owner"],
            lease_expires_at=_dt(row["lease_expires_at"]),
            dead_lettered_at=_dt(row["dead_lettered_at"]),
            replay_count=int(row["replay_count"]),
            last_error=row["last_error"],
        )

    @staticmethod
    def append_in_transaction(
        connection: sqlite3.Connection,
        *,
        tenant_id: str,
        aggregate_id: str,
        source: str,
        event_type: str,
        payload: bytes,
        idempotency_key: str,
        max_attempts: int = 5,
        event_id: str | None = None,
        now: datetime | None = None,
    ) -> SQLiteOutboxRecord:
        """Append within a caller-owned transaction for atomic journal + outbox commits."""
        if not connection.in_transaction:
            raise RuntimeError("append_in_transaction requires an active SQLite transaction")
        _normalized(aggregate_id, "aggregate_id")
        _normalized(idempotency_key, "idempotency_key")
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        resolved_id, digest, canonical, resolved_type = _validate_envelope(
            tenant_id=tenant_id,
            source=source,
            event_type=event_type,
            payload=payload,
            event_id=event_id,
        )
        if resolved_type != event_type:
            raise EventDeliveryConflictError("event type conflicts with envelope")
        current_time = now or datetime.now(UTC)
        existing = connection.execute(
            "SELECT * FROM platform_event_outbox WHERE tenant_id=? AND idempotency_key=?",
            (tenant_id, idempotency_key),
        ).fetchone()
        if existing is not None:
            record = SQLiteTransactionalOutbox._decode(existing)
            if (
                record.payload_digest != digest
                or record.source != source
                or record.event_id != resolved_id
                or record.aggregate_id != aggregate_id
                or record.event_type != event_type
            ):
                raise EventDeliveryConflictError("idempotency key was reused with different event content")
            return record
        by_event = connection.execute(
            "SELECT * FROM platform_event_outbox WHERE source=? AND event_id=?",
            (source, resolved_id),
        ).fetchone()
        if by_event is not None:
            record = SQLiteTransactionalOutbox._decode(by_event)
            if record.payload_digest != digest or record.tenant_id != tenant_id:
                raise EventDeliveryConflictError("event identity was reused with different content or tenant")
            return record
        connection.execute(
            """
            INSERT INTO platform_event_outbox (
                event_id,source,tenant_id,aggregate_id,event_type,payload,payload_digest,
                idempotency_key,created_at,attempts,max_attempts,next_attempt_at,published_at,
                lease_id,lease_owner,lease_expires_at,dead_lettered_at,replay_count,last_error
            ) VALUES (?,?,?,?,?,?,?,?,?,0,?,?,NULL,NULL,NULL,NULL,NULL,0,NULL)
            """,
            (
                resolved_id, source, tenant_id, aggregate_id, event_type, canonical, digest,
                idempotency_key, current_time.isoformat(), max_attempts, current_time.isoformat(),
            ),
        )
        row = connection.execute(
            "SELECT * FROM platform_event_outbox WHERE source=? AND event_id=?",
            (source, resolved_id),
        ).fetchone()
        assert row is not None
        return SQLiteTransactionalOutbox._decode(row)

    def append(
        self,
        *,
        tenant_id: str,
        aggregate_id: str,
        source: str,
        event_type: str,
        payload: bytes,
        idempotency_key: str,
        event_id: str | None = None,
        max_attempts: int | None = None,
    ) -> SQLiteOutboxRecord:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            record = self.append_in_transaction(
                db,
                tenant_id=tenant_id,
                aggregate_id=aggregate_id,
                source=source,
                event_type=event_type,
                payload=payload,
                idempotency_key=idempotency_key,
                max_attempts=max_attempts or self.max_attempts,
                event_id=event_id,
                now=self._clock(),
            )
            db.commit()
        return record

    def lease(
        self,
        owner: str,
        *,
        limit: int = 100,
        ttl_seconds: float = 30.0,
    ) -> tuple[SQLiteOutboxRecord, ...]:
        _normalized(owner, "lease owner")
        if limit < 1 or ttl_seconds <= 0:
            raise ValueError("positive lease limit and TTL are required")
        now = self._clock()
        expires = now + timedelta(seconds=ttl_seconds)
        leased: list[SQLiteOutboxRecord] = []
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """
                UPDATE platform_event_outbox
                SET dead_lettered_at=?, lease_id=NULL, lease_owner=NULL, lease_expires_at=NULL
                WHERE published_at IS NULL AND dead_lettered_at IS NULL
                  AND attempts >= max_attempts
                  AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?
                """,
                (now.isoformat(), now.isoformat()),
            )
            rows = db.execute(
                """
                SELECT source,event_id FROM platform_event_outbox
                WHERE published_at IS NULL AND dead_lettered_at IS NULL
                  AND next_attempt_at <= ?
                  AND attempts < max_attempts
                  AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
                ORDER BY created_at,source,event_id LIMIT ?
                """,
                (now.isoformat(), now.isoformat(), limit),
            ).fetchall()
            for row in rows:
                lease_id = str(uuid4())
                db.execute(
                    """
                    UPDATE platform_event_outbox
                    SET attempts=attempts+1,lease_id=?,lease_owner=?,lease_expires_at=?
                    WHERE source=? AND event_id=?
                    """,
                    (lease_id, owner, expires.isoformat(), row["source"], row["event_id"]),
                )
                record = db.execute(
                    "SELECT * FROM platform_event_outbox WHERE source=? AND event_id=?",
                    (row["source"], row["event_id"]),
                ).fetchone()
                assert record is not None
                leased.append(self._decode(record))
            db.commit()
        return tuple(leased)

    def acknowledge(self, source: str, event_id: str, lease_id: str, owner: str) -> None:
        now = self._clock()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM platform_event_outbox WHERE source=? AND event_id=?",
                (source, event_id),
            ).fetchone()
            if row is None:
                raise KeyError("outbox event does not exist")
            record = self._decode(row)
            if (
                record.lease_id != lease_id
                or record.lease_owner != owner
                or record.lease_expires_at is None
                or record.lease_expires_at <= now
                or record.published_at is not None
                or record.dead_lettered_at is not None
            ):
                raise PermissionError("outbox acknowledgement does not match an active lease")
            db.execute(
                """
                UPDATE platform_event_outbox
                SET published_at=?,lease_id=NULL,lease_owner=NULL,lease_expires_at=NULL,last_error=NULL
                WHERE source=? AND event_id=?
                """,
                (now.isoformat(), source, event_id),
            )
            db.commit()

    def fail(
        self,
        source: str,
        event_id: str,
        lease_id: str,
        owner: str,
        error_code: str,
    ) -> datetime | None:
        _normalized(error_code, "error_code", 256)
        now = self._clock()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM platform_event_outbox WHERE source=? AND event_id=?",
                (source, event_id),
            ).fetchone()
            if row is None:
                raise KeyError("outbox event does not exist")
            record = self._decode(row)
            if (
                record.lease_id != lease_id
                or record.lease_owner != owner
                or record.lease_expires_at is None
                or record.lease_expires_at <= now
                or record.published_at is not None
                or record.dead_lettered_at is not None
            ):
                raise PermissionError("outbox failure does not match an active lease")
            if record.attempts >= record.max_attempts:
                db.execute(
                    """
                    UPDATE platform_event_outbox
                    SET dead_lettered_at=?,lease_id=NULL,lease_owner=NULL,lease_expires_at=NULL,last_error=?
                    WHERE source=? AND event_id=?
                    """,
                    (now.isoformat(), error_code, source, event_id),
                )
                db.commit()
                return None
            delay = min(
                self.base_delay_seconds * (2 ** max(record.attempts - 1, 0)),
                self.max_delay_seconds,
            )
            next_attempt = now + timedelta(seconds=delay)
            db.execute(
                """
                UPDATE platform_event_outbox
                SET next_attempt_at=?,lease_id=NULL,lease_owner=NULL,lease_expires_at=NULL,last_error=?
                WHERE source=? AND event_id=?
                """,
                (next_attempt.isoformat(), error_code, source, event_id),
            )
            db.commit()
            return next_attempt

    def pending(self, tenant_id: str, *, limit: int = 100) -> tuple[SQLiteOutboxRecord, ...]:
        _normalized(tenant_id, "tenant_id")
        if limit < 1:
            raise ValueError("limit must be positive")
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT * FROM platform_event_outbox
                WHERE tenant_id=? AND published_at IS NULL AND dead_lettered_at IS NULL
                ORDER BY created_at LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
        return tuple(self._decode(row) for row in rows)

    def dead_letters(self, tenant_id: str, *, limit: int = 100) -> tuple[SQLiteOutboxRecord, ...]:
        _normalized(tenant_id, "tenant_id")
        if limit < 1:
            raise ValueError("limit must be positive")
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT * FROM platform_event_outbox
                WHERE tenant_id=? AND dead_lettered_at IS NOT NULL
                ORDER BY dead_lettered_at LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
        return tuple(self._decode(row) for row in rows)

    def replay(
        self,
        tenant_id: str,
        source: str,
        event_id: str,
        *,
        actor_id: str,
        reason: str,
    ) -> SQLiteOutboxRecord:
        _normalized(tenant_id, "tenant_id")
        _normalized(actor_id, "actor_id")
        _normalized(reason, "replay reason", 1024)
        now = self._clock()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM platform_event_outbox WHERE tenant_id=? AND source=? AND event_id=?",
                (tenant_id, source, event_id),
            ).fetchone()
            if row is None:
                raise KeyError("outbox event is not owned by tenant")
            record = self._decode(row)
            if record.dead_lettered_at is None or record.published_at is not None:
                raise ValueError("only unpublished dead-letter events can be replayed")
            db.execute(
                """
                INSERT INTO platform_outbox_replay_log
                    (replay_id,tenant_id,source,event_id,actor_id,reason,replayed_at)
                VALUES (?,?,?,?,?,?,?)
                """,
                (str(uuid4()), tenant_id, source, event_id, actor_id, reason, now.isoformat()),
            )
            db.execute(
                """
                UPDATE platform_event_outbox
                SET attempts=0,next_attempt_at=?,dead_lettered_at=NULL,replay_count=replay_count+1,
                    lease_id=NULL,lease_owner=NULL,lease_expires_at=NULL,last_error=NULL
                WHERE tenant_id=? AND source=? AND event_id=?
                """,
                (now.isoformat(), tenant_id, source, event_id),
            )
            updated = db.execute(
                "SELECT * FROM platform_event_outbox WHERE tenant_id=? AND source=? AND event_id=?",
                (tenant_id, source, event_id),
            ).fetchone()
            assert updated is not None
            db.commit()
        return self._decode(updated)


class SQLiteEventInbox:
    """Durable consumer deduplication; call consume_in_transaction with consumer state writes."""

    def __init__(self, path: str | Path, *, clock: Callable[[], datetime] | None = None) -> None:
        if not str(path).strip():
            raise ValueError("inbox database path is required")
        self.path = str(path)
        self._clock = clock or (lambda: datetime.now(UTC))
        with self._connect() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS platform_event_inbox (
                    tenant_id TEXT NOT NULL,
                    consumer_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    processed_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, consumer_id, source, event_id)
                )
                """
            )
            db.commit()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10.0)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=10000")
        return db

    @staticmethod
    def consume_in_transaction(
        connection: sqlite3.Connection,
        *,
        tenant_id: str,
        consumer_id: str,
        source: str,
        event_id: str,
        payload: bytes,
        processed_at: datetime | None = None,
    ) -> bool:
        """Return True for first delivery, False for a byte-equivalent duplicate."""
        if not connection.in_transaction:
            raise RuntimeError("consume_in_transaction requires an active SQLite transaction")
        for value, name in (
            (tenant_id, "tenant_id"),
            (consumer_id, "consumer_id"),
            (source, "source"),
            (event_id, "event_id"),
        ):
            _normalized(value, name, 2048)
        if not isinstance(payload, bytes) or not payload or len(payload) > MAX_EVENT_BYTES:
            raise ValueError("inbox payload must be non-empty bytes no larger than 1 MiB")
        digest = hashlib.sha256(payload).hexdigest()
        existing = connection.execute(
            """
            SELECT payload_digest FROM platform_event_inbox
            WHERE tenant_id=? AND consumer_id=? AND source=? AND event_id=?
            """,
            (tenant_id, consumer_id, source, event_id),
        ).fetchone()
        if existing is not None:
            if existing["payload_digest"] != digest:
                raise EventDeliveryConflictError("consumer inbox identity was reused with different payload")
            return False
        connection.execute(
            """
            INSERT INTO platform_event_inbox
                (tenant_id,consumer_id,source,event_id,payload_digest,processed_at)
            VALUES (?,?,?,?,?,?)
            """,
            (
                tenant_id,
                consumer_id,
                source,
                event_id,
                digest,
                (processed_at or datetime.now(UTC)).isoformat(),
            ),
        )
        return True

    def consume(
        self,
        *,
        tenant_id: str,
        consumer_id: str,
        source: str,
        event_id: str,
        payload: bytes,
    ) -> bool:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            result = self.consume_in_transaction(
                db,
                tenant_id=tenant_id,
                consumer_id=consumer_id,
                source=source,
                event_id=event_id,
                payload=payload,
                processed_at=self._clock(),
            )
            db.commit()
        return result

    def contains(self, tenant_id: str, consumer_id: str, source: str, event_id: str) -> bool:
        _normalized(tenant_id, "tenant_id")
        with self._connect() as db:
            row = db.execute(
                """
                SELECT 1 FROM platform_event_inbox
                WHERE tenant_id=? AND consumer_id=? AND source=? AND event_id=?
                """,
                (tenant_id, consumer_id, source, event_id),
            ).fetchone()
        return row is not None
