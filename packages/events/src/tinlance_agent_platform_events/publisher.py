"""Tenant-scoped PostgreSQL outbox publisher.

The transport is injected. Database transactions only claim, read, acknowledge,
or release outbox records; network publication never occurs inside a database
transaction. Delivery is at-least-once, so consumers must deduplicate.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from .envelope import CloudEventEnvelope

ConnectionFactory = Callable[[], Any]
TransportPublish = Callable[[CloudEventEnvelope], None]
_SENSITIVE_MARKERS = (
    "secret",
    "password",
    "token",
    "api_key",
    "private_key",
    "credential",
)


@dataclass(frozen=True, slots=True)
class OutboxPollResult:
    claimed: int
    published: int
    failed: int
    acknowledgement_failed: int


def _contains_sensitive_marker(value: object) -> bool:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if any(marker in str(key).lower() for marker in _SENSITIVE_MARKERS):
                return True
            if _contains_sensitive_marker(nested):
                return True
        return False
    if isinstance(value, (list, tuple)):
        return any(_contains_sensitive_marker(item) for item in value)
    if isinstance(value, str):
        return any(marker in value.lower() for marker in _SENSITIVE_MARKERS)
    return False


class PostgresOutboxPublisher:
    """Polls a tenant's durable outbox using lease-checked database functions."""

    def __init__(
        self,
        *,
        tenant_id: str,
        connection_factory: ConnectionFactory,
        publish: TransportPublish,
        retry_base_seconds: int = 1,
    ) -> None:
        if not tenant_id or tenant_id != tenant_id.strip():
            raise ValueError("tenant_id must be normalized and non-empty")
        try:
            self._tenant_id = str(UUID(tenant_id))
        except ValueError as exc:
            raise ValueError("tenant_id must be a UUID") from exc
        if retry_base_seconds < 0 or retry_base_seconds > 3600:
            raise ValueError("retry_base_seconds must be between 0 and 3600")
        self._connection_factory = connection_factory
        self._publish = publish
        self._retry_base_seconds = retry_base_seconds

    @contextmanager
    def _transaction(self) -> Iterator[Any]:
        connection = self._connection_factory()
        try:
            if getattr(connection, "autocommit", False):
                info = getattr(connection, "info", None)
                status = getattr(info, "transaction_status", None)
                if status is None or int(status) == 0:
                    raise RuntimeError("outbox operations require a transactional connection")
            connection.execute(
                "SELECT set_config('platform.tenant_id', %s, true)",
                (self._tenant_id,),
            )
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def poll_once(self, *, limit: int = 100, lease_seconds: int = 30) -> OutboxPollResult:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if lease_seconds < 1 or lease_seconds > 3600:
            raise ValueError("lease_seconds must be between 1 and 3600")
        claims = self._claim(limit=limit, lease_seconds=lease_seconds)
        published = 0
        failed = 0
        acknowledgement_failed = 0
        for outbox_id, event_id, lease_token, _attempts in claims:
            try:
                envelope = self._load_envelope(event_id)
                if envelope is None:
                    raise ValueError("outbox row references a missing event")
                self._publish(envelope)
            except Exception as exc:
                error_code = (
                    "event_invalid"
                    if isinstance(exc, (ValueError, TypeError, json.JSONDecodeError))
                    else "provider_publish_failed"
                )
                # Leave the lease to expire; never persist raw exception text.
                with suppress(Exception):
                    self._release(outbox_id, lease_token, error_code)
                failed += 1
                continue
            try:
                acknowledged = self._acknowledge(outbox_id, lease_token)
            except Exception:
                acknowledged = False
            if acknowledged:
                published += 1
            else:
                # The publish may have succeeded; a duplicate after lease expiry is expected.
                acknowledgement_failed += 1
        return OutboxPollResult(len(claims), published, failed, acknowledgement_failed)

    def _claim(self, *, limit: int, lease_seconds: int) -> list[tuple[Any, ...]]:
        with self._transaction() as connection:
            cursor = connection.execute(
                "SELECT outbox_id, event_id, lease_token, attempts "
                "FROM platform.claim_outbox_batch(%s, %s)",
                (limit, lease_seconds),
            )
            return list(cursor.fetchall())

    def _load_envelope(self, event_id: UUID | str) -> CloudEventEnvelope | None:
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT event_id, tenant_id, run_id, event_type, payload, occurred_at, source, "
                "correlation_id, causation_id, trace_id, span_id, schema_uri, data_classification "
                "FROM platform.events WHERE tenant_id = %s AND event_id = %s",
                (UUID(self._tenant_id), event_id),
            ).fetchone()
        if row is None:
            return None
        (
            stored_event_id,
            stored_tenant_id,
            run_id,
            event_type,
            payload_value,
            occurred_at,
            source,
            correlation_id,
            causation_id,
            trace_id,
            span_id,
            schema_uri,
            data_classification,
        ) = row
        if str(stored_tenant_id) != self._tenant_id:
            raise ValueError("event tenant does not match the active outbox tenant")
        payload = json.loads(payload_value) if isinstance(payload_value, str) else payload_value
        if not isinstance(payload, Mapping):
            raise ValueError("event payload must be a JSON object")
        if _contains_sensitive_marker(payload):
            raise ValueError("event payload contains a prohibited sensitive marker")
        if isinstance(occurred_at, str):
            occurred_at = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
        if not isinstance(occurred_at, datetime) or occurred_at.tzinfo is None:
            raise ValueError("event timestamp must be timezone-aware")
        if not isinstance(trace_id, str) or not trace_id.strip():
            raise ValueError("event trace context is missing")
        if not isinstance(correlation_id, str) or not correlation_id.strip():
            raise ValueError("event correlation context is missing")
        return CloudEventEnvelope(
            id=str(stored_event_id),
            source=str(source),
            type=str(event_type),
            time=occurred_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            tenantid=self._tenant_id,
            executionid=str(run_id),
            traceid=trace_id.strip(),
            correlationid=correlation_id.strip(),
            data=payload,
            spanid=str(span_id).strip() if span_id is not None else None,
            causationid=str(causation_id).strip() if causation_id is not None else None,
            dataclassification=str(data_classification),
            dataschema=str(schema_uri).strip() if schema_uri is not None else None,
        )

    def _acknowledge(self, outbox_id: UUID | str, lease_token: UUID | str) -> bool:
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT platform.ack_outbox(%s, %s)",
                (outbox_id, lease_token),
            ).fetchone()
        return bool(row and row[0] is True)

    def _release(
        self, outbox_id: UUID | str, lease_token: UUID | str, error_code: str
    ) -> bool:
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT platform.release_outbox(%s, %s, %s, %s)",
                (outbox_id, lease_token, error_code, self._retry_base_seconds),
            ).fetchone()
        return bool(row and row[0] is True)
