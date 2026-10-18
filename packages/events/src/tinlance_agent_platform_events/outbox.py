"""In-memory and transaction-bound PostgreSQL event stores.

PostgresEventStore never opens, commits, or rolls back a transaction. The caller
must pass the same tenant-scoped connection used for the domain state transition,
so the state change, event row, and outbox row commit or roll back together.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from threading import RLock
from types import MappingProxyType
from typing import Any, Protocol
from uuid import UUID, uuid4

from .envelope import CloudEventEnvelope


@dataclass(frozen=True, slots=True)
class Event:
    event_id: UUID
    tenant_id: str
    run_id: UUID
    event_type: str
    payload: Mapping[str, str]
    occurred_at: datetime
    source: str = "urn:tinlance:agent-platform"
    correlation_id: str | None = None
    causation_id: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    schema_uri: str | None = None
    data_classification: str = "internal"


class EventStore(Protocol):
    """Structural contract shared by in-memory and PostgreSQL stores."""

    def append(self, event: Event) -> Event: ...

    def list_for_run(self, tenant_id: str, run_id: UUID) -> tuple[Event, ...]: ...


def _prepare_event(event: Event) -> tuple[Event, CloudEventEnvelope]:
    if (
        not event.tenant_id
        or event.tenant_id != event.tenant_id.strip()
        or not event.event_type
        or event.event_type != event.event_type.strip()
        or event.occurred_at.tzinfo is None
        or event.occurred_at.utcoffset() is None
    ):
        raise ValueError("invalid event identity or timestamp")
    if len(event.payload) > 64:
        raise ValueError("event payload has too many fields")
    if any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in event.payload.items()
    ):
        raise ValueError("event payload keys and values must be strings")
    sensitive_markers = (
        "secret", "password", "token", "api_key", "private_key", "credential"
    )
    if any(
        any(marker in key.lower() or marker in value.lower() for marker in sensitive_markers)
        for key, value in event.payload.items()
    ):
        raise ValueError("sensitive event fields are forbidden")
    trace_id = event.trace_id or uuid4().hex
    correlation_id = event.correlation_id or str(event.run_id)
    stored = replace(
        event,
        payload=MappingProxyType(dict(event.payload)),
        correlation_id=correlation_id,
        trace_id=trace_id,
        occurred_at=event.occurred_at.astimezone(UTC),
    )
    envelope = CloudEventEnvelope(
        id=str(stored.event_id),
        source=stored.source,
        type=stored.event_type,
        time=stored.occurred_at.isoformat().replace("+00:00", "Z"),
        tenantid=stored.tenant_id,
        executionid=str(stored.run_id),
        traceid=trace_id,
        correlationid=correlation_id,
        data=stored.payload,
        spanid=stored.span_id,
        causationid=stored.causation_id,
        dataschema=stored.schema_uri,
        dataclassification=stored.data_classification,
    )
    # Envelope validation is intentional even though the payload is not persisted here.
    envelope.as_payload()
    return stored, envelope


class InMemoryEventStore:
    """Thread-safe reference store for unit tests and local development only."""

    def __init__(self) -> None:
        self._events: list[Event] = []
        self._ids: set[UUID] = set()
        self._lock = RLock()

    def append(self, event: Event) -> Event:
        stored, _ = _prepare_event(event)
        with self._lock:
            if stored.event_id in self._ids:
                raise ValueError("event id already exists")
            self._events.append(stored)
            self._ids.add(stored.event_id)
        return stored

    def list_for_run(self, tenant_id: str, run_id: UUID) -> tuple[Event, ...]:
        if not tenant_id or tenant_id != tenant_id.strip():
            raise ValueError("tenant identifier must be normalized")
        with self._lock:
            return tuple(
                event
                for event in self._events
                if event.tenant_id == tenant_id and event.run_id == run_id
            )


class PostgresEventStore:
    """PostgreSQL adapter bound to a caller-owned tenant-scoped transaction.

    The supplied connection must already be in the same transaction as the
    domain state mutation. This class intentionally never commits or closes it.
    """

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def append(self, event: Event) -> Event:
        stored, _ = _prepare_event(event)
        try:
            tenant_uuid = UUID(stored.tenant_id)
        except ValueError as exc:
            raise ValueError("PostgreSQL tenant_id must be a UUID") from exc

        run = self._connection.execute(
            "SELECT run_id FROM platform.runs "
            "WHERE tenant_id = %s AND run_id = %s FOR UPDATE",
            (tenant_uuid, stored.run_id),
        ).fetchone()
        if run is None:
            raise ValueError("run does not exist in the supplied tenant scope")

        sequence_row = self._connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) + 1 "
            "FROM platform.events WHERE tenant_id = %s AND run_id = %s",
            (tenant_uuid, stored.run_id),
        ).fetchone()
        if sequence_row is None or not isinstance(sequence_row[0], int):
            raise RuntimeError("could not allocate a run event sequence")
        sequence = sequence_row[0]
        payload_json = json.dumps(
            dict(stored.payload), sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        self._connection.execute(
            "INSERT INTO platform.events "
            "(event_id, tenant_id, run_id, event_type, payload, sequence, occurred_at, "
            "source, correlation_id, causation_id, trace_id, span_id, schema_uri, data_classification) "
            "VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                stored.event_id,
                tenant_uuid,
                stored.run_id,
                stored.event_type,
                payload_json,
                sequence,
                stored.occurred_at,
                stored.source,
                stored.correlation_id,
                stored.causation_id,
                stored.trace_id,
                stored.span_id,
                stored.schema_uri,
                stored.data_classification,
            ),
        )
        self._connection.execute(
            "INSERT INTO platform.outbox (outbox_id, tenant_id, event_id, available_at, attempts) "
            "VALUES (%s, %s, %s, %s, 0)",
            (uuid4(), tenant_uuid, stored.event_id, stored.occurred_at),
        )
        return stored

    def list_for_run(self, tenant_id: str, run_id: UUID) -> tuple[Event, ...]:
        if not tenant_id or tenant_id != tenant_id.strip():
            raise ValueError("tenant identifier must be normalized")
        try:
            tenant_uuid = UUID(tenant_id)
        except ValueError as exc:
            raise ValueError("PostgreSQL tenant_id must be a UUID") from exc
        rows = self._connection.execute(
            "SELECT event_id, tenant_id, run_id, event_type, payload, occurred_at, source, "
            "correlation_id, causation_id, trace_id, span_id, schema_uri, data_classification "
            "FROM platform.events WHERE tenant_id = %s AND run_id = %s ORDER BY sequence",
            (tenant_uuid, run_id),
        ).fetchall()
        result: list[Event] = []
        for row in rows:
            payload_value = row[4]
            payload = json.loads(payload_value) if isinstance(payload_value, str) else payload_value
            if not isinstance(payload, Mapping) or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in payload.items()
            ):
                raise ValueError("stored event payload violates the event contract")
            occurred_at = row[5]
            if isinstance(occurred_at, str):
                occurred_at = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
            if not isinstance(occurred_at, datetime):
                raise ValueError("stored event timestamp is invalid")
            result.append(
                Event(
                    event_id=UUID(str(row[0])),
                    tenant_id=str(row[1]),
                    run_id=UUID(str(row[2])),
                    event_type=str(row[3]),
                    payload=MappingProxyType(dict(payload)),
                    occurred_at=occurred_at,
                    source=str(row[6]),
                    correlation_id=str(row[7]) if row[7] is not None else None,
                    causation_id=str(row[8]) if row[8] is not None else None,
                    trace_id=str(row[9]) if row[9] is not None else None,
                    span_id=str(row[10]) if row[10] is not None else None,
                    schema_uri=str(row[11]) if row[11] is not None else None,
                    data_classification=str(row[12]),
                )
            )
        return tuple(result)


def new_event(
    tenant_id: str,
    run_id: UUID,
    event_type: str,
    payload: Mapping[str, str],
) -> Event:
    if not tenant_id or tenant_id != tenant_id.strip():
        raise ValueError("tenant identifier must be normalized")
    if not event_type or event_type != event_type.strip():
        raise ValueError("event type must be normalized")
    return Event(
        uuid4(),
        tenant_id,
        run_id,
        event_type,
        MappingProxyType(dict(payload)),
        datetime.now(UTC),
        correlation_id=str(run_id),
        trace_id=uuid4().hex,
    )
