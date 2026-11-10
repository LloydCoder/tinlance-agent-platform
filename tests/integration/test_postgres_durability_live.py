from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest

from tinlance_agent_platform_durability.postgres_restore_ledger import PostgresRestoreLedger
from tinlance_agent_platform_durability.postgres_snapshot_catalog import PostgresSnapshotCatalog
from tinlance_agent_platform_durability.snapshots import SnapshotConflictError, SnapshotReference
from tinlance_agent_platform_events.publisher import PostgresOutboxPublisher

DATABASE_URL = os.getenv("FCP03_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="FCP03 live PostgreSQL URL is not configured")
_APP_ROLE = "fcp03_adapter_runtime"


@pytest.fixture(scope="session", autouse=True)
def _configure_runtime_role() -> None:
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL, autocommit=True) as connection:
        connection.execute(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{_APP_ROLE}') THEN
                    CREATE ROLE {_APP_ROLE} NOLOGIN;
                END IF;
            END
            $$;
            """
        )
        connection.execute(f"GRANT USAGE ON SCHEMA platform TO {_APP_ROLE}")
        connection.execute(
            f"""
            GRANT SELECT ON platform.events, platform.outbox, platform.workspace_leases,
                platform.workspace_snapshots, platform.workspace_restore_operations
            TO {_APP_ROLE}
            """
        )
        connection.execute(
            f"""
            GRANT INSERT, UPDATE ON platform.outbox, platform.workspace_restore_operations
            TO {_APP_ROLE}
            """
        )
        connection.execute(
            f"""
            GRANT INSERT ON platform.workspace_snapshots, platform.workspace_snapshot_events,
                platform.workspace_restore_operations, platform.workspace_restore_events
            TO {_APP_ROLE}
            """
        )
        connection.execute(
            f"""
            GRANT EXECUTE ON FUNCTION platform.claim_outbox_batch(integer, integer),
                platform.ack_outbox(uuid, uuid),
                platform.release_outbox(uuid, uuid, text, integer),
                platform.record_workspace_snapshot(uuid, uuid, uuid, bigint, timestamptz, text, text),
                platform.get_workspace_snapshot(uuid, uuid, uuid),
                platform.begin_workspace_restore(uuid, uuid, uuid, uuid, bigint),
                platform.complete_workspace_restore(uuid, uuid, uuid, text),
                platform.fail_workspace_restore(uuid, uuid, uuid, text)
            TO {_APP_ROLE}
            """
        )


def _admin_connection():
    assert DATABASE_URL is not None
    return psycopg.connect(DATABASE_URL)


def _app_connection():
    connection = _admin_connection()
    connection.execute(f"SET ROLE {_APP_ROLE}")
    return connection


def _seed_tenant(*, label: str) -> tuple[object, object, object, object]:
    tenant_id, agent_id, task_id, run_id = uuid4(), uuid4(), uuid4(), uuid4()
    with _admin_connection() as connection:
        connection.execute(
            "INSERT INTO platform.tenants (tenant_id, name) VALUES (%s, %s)",
            (tenant_id, f"fcp03-{label}-{tenant_id.hex}"),
        )
        connection.execute(
            """
            INSERT INTO platform.agents (
                agent_id, tenant_id, agent_type, version, owner_subject_id,
                policy_profile, trust_level, environment
            ) VALUES (%s, %s, 'research', '1.0.0', 'fcp03-owner', 'default', 'standard', 'test')
            """,
            (agent_id, tenant_id),
        )
        connection.execute(
            """
            INSERT INTO platform.tasks (
                task_id, tenant_id, agent_id, agent_version, requester_subject_id,
                status, objective
            ) VALUES (%s, %s, %s, '1.0.0', 'fcp03-owner', 'queued', 'FCP-03 live adapter qualification')
            """,
            (task_id, tenant_id, agent_id),
        )
        connection.execute(
            "INSERT INTO platform.runs (run_id, tenant_id, task_id, status) VALUES (%s, %s, %s, 'created')",
            (run_id, tenant_id, task_id),
        )
    return tenant_id, agent_id, task_id, run_id


def _seed_workspace_lease(tenant_id, workspace_id, *, fence: int = 7) -> None:
    with _admin_connection() as connection:
        connection.execute(
            """
            INSERT INTO platform.workspace_leases (
                tenant_id, workspace_id, lease_id, owner_subject_id, worker_id,
                fencing_token, status, lease_expires_at
            ) VALUES (%s, %s, %s, 'fcp03-owner', 'fcp03-worker', %s, 'active', %s)
            """,
            (tenant_id, workspace_id, uuid4(), fence, datetime.now(UTC) + timedelta(hours=1)),
        )


def test_live_postgres_outbox_publisher_claims_acknowledges_and_releases_by_tenant() -> None:
    tenant_a, _, _, run_a = _seed_tenant(label="outbox-a")
    tenant_b, _, _, run_b = _seed_tenant(label="outbox-b")
    event_a_ok, event_a_fail, event_b = uuid4(), uuid4(), uuid4()
    outbox_a_ok, outbox_a_fail, outbox_b = uuid4(), uuid4(), uuid4()
    now = datetime.now(UTC)

    with _admin_connection() as connection:
        for tenant_id, run_id, event_id, event_type in (
            (tenant_a, run_a, event_a_ok, "execution.completed"),
            (tenant_a, run_a, event_a_fail, "execution.failed"),
            (tenant_b, run_b, event_b, "execution.completed"),
        ):
            connection.execute(
                """
                INSERT INTO platform.events (
                    event_id, tenant_id, run_id, event_type, payload, sequence,
                    occurred_at, source, correlation_id, trace_id
                ) VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s,
                          'https://tinlance.com/platform/runs', %s, %s)
                """,
                (
                    event_id,
                    tenant_id,
                    run_id,
                    event_type,
                    '{"state":"completed"}',
                    1 if event_id == event_a_ok else 2 if event_id == event_a_fail else 1,
                    now,
                    f"correlation-{event_id.hex}",
                    "4bf92f3577b34da6a3ce929d0e0e4736",
                ),
            )
        connection.executemany(
            """
            INSERT INTO platform.outbox (outbox_id, tenant_id, event_id, max_attempts)
            VALUES (%s, %s, %s, 5)
            """,
            (
                (outbox_a_ok, tenant_a, event_a_ok),
                (outbox_a_fail, tenant_a, event_a_fail),
                (outbox_b, tenant_b, event_b),
            ),
        )

    published: list[str] = []

    def publish(envelope) -> None:
        if envelope.type == "execution.failed":
            raise RuntimeError("provider rejected secret token=must-not-be-persisted")
        published.append(envelope.id)

    publisher = PostgresOutboxPublisher(
        tenant_id=str(tenant_a),
        connection_factory=_app_connection,
        publish=publish,
        retry_base_seconds=0,
    )
    result = publisher.poll_once(limit=10, lease_seconds=30)

    assert result.claimed == 2
    assert result.published == 1
    assert result.failed == 1
    assert result.acknowledgement_failed == 0
    assert published == [str(event_a_ok)]

    with _admin_connection() as connection:
        rows = connection.execute(
            """
            SELECT o.outbox_id, o.published_at, o.last_error_code, o.lease_token, o.attempts
              FROM platform.outbox AS o
             WHERE o.outbox_id = ANY(%s)
            """,
            ([outbox_a_ok, outbox_a_fail, outbox_b],),
        ).fetchall()
    state = {row[0]: row[1:] for row in rows}
    assert state[outbox_a_ok][0] is not None
    assert state[outbox_a_ok][1] is None
    assert state[outbox_a_fail][0] is None
    assert state[outbox_a_fail][1] == "provider_publish_failed"
    assert state[outbox_a_fail][2] is None
    assert state[outbox_a_fail][3] == 1
    assert state[outbox_b][0] is None
    assert state[outbox_b][3] == 0


def test_live_postgres_snapshot_catalog_and_restore_ledger_enforce_tenant_scope() -> None:
    tenant_a, _, _, _ = _seed_tenant(label="restore-a")
    tenant_b, _, _, _ = _seed_tenant(label="restore-b")
    workspace_id = uuid4()
    snapshot_id = uuid4()
    restore_id = uuid4()
    restore_fail_id = uuid4()
    digest = "a" * 64
    _seed_workspace_lease(tenant_a, workspace_id)

    catalog = PostgresSnapshotCatalog(connection_factory=_app_connection)
    reference = SnapshotReference(
        snapshot_id=snapshot_id,
        tenant_id=tenant_a,
        workspace_id=workspace_id,
        fencing_token=7,
        created_at=datetime.now(UTC),
        digest=digest,
    )
    catalog.record(reference)
    assert catalog.get(tenant_a, workspace_id, snapshot_id) == reference
    with pytest.raises(SnapshotConflictError):
        catalog.record(reference)

    ledger = PostgresRestoreLedger(connection_factory=_app_connection)
    assert ledger.begin(tenant_a, workspace_id, restore_id, snapshot_id, 7) is True
    assert ledger.begin(tenant_a, workspace_id, restore_id, snapshot_id, 7) is False
    ledger.complete(tenant_a, workspace_id, restore_id, digest)
    ledger.complete(tenant_a, workspace_id, restore_id, digest)

    assert catalog.get(tenant_b, workspace_id, snapshot_id) is None

    assert ledger.begin(tenant_a, workspace_id, restore_fail_id, snapshot_id, 7) is True
    ledger.fail(tenant_a, workspace_id, restore_fail_id, "provider_restore_failed")

    with _admin_connection() as connection:
        states = connection.execute(
            """
            SELECT restore_id, status, snapshot_digest, failure_code
              FROM platform.workspace_restore_operations
             WHERE tenant_id = %s AND restore_id = ANY(%s)
            """,
            (tenant_a, [restore_id, restore_fail_id]),
        ).fetchall()
    state = {row[0]: row[1:] for row in states}
    assert state[restore_id] == ("completed", digest, None)
    assert state[restore_fail_id] == ("failed", None, "provider_restore_failed")
