from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from tinlance_agent_platform_approvals import PostgresApprovalService
from tinlance_agent_platform_contracts import ApprovalStatus

TENANT_ID = UUID("00000000-0000-0000-0000-000000000091")
RUN_ID = UUID("40000000-0000-0000-0000-000000000091")
APPROVAL_ID = UUID("50000000-0000-0000-0000-000000000091")
FINGERPRINT = "a" * 64


class Cursor:
    def __init__(self, row=None):
        self.row = row

    def fetchone(self):
        return self.row


class Connection:
    def __init__(self, *, selected=None, inserted=None, updated=None):
        self.selected = selected
        self.inserted = inserted
        self.updated = updated
        self.queries = []
        self.committed = False
        self.rolled_back = False
        self.closed = False
        self.autocommit = False

    def execute(self, query, params=()):
        self.queries.append((query, params))
        if "INSERT INTO platform.action_approvals" in query:
            return Cursor(self.inserted)
        if "SELECT approval_id" in query and "platform.action_approvals" in query:
            return Cursor(self.selected)
        if "UPDATE platform.action_approvals" in query:
            return Cursor(self.updated)
        return Cursor(("ok",))

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def approval_row(
    status="pending",
    *,
    expires_at=None,
    approved_by=None,
    consumed_at=None,
):
    return (
        APPROVAL_ID,
        TENANT_ID,
        RUN_ID,
        "replay",
        "extensions://outbox/dead-letters/{event_id}",
        "Replay dead-letter event",
        "requester-a",
        status,
        {},
        expires_at,
        FINGERPRINT,
        approved_by,
        consumed_at,
    )


def test_postgres_approval_request_persists_tenant_bound_intent_and_event():
    row = approval_row()
    connection = Connection(inserted=row)
    service = PostgresApprovalService(connection_factory=lambda: connection)

    result = service.request(
        str(TENANT_ID),
        RUN_ID,
        "replay",
        "extensions://outbox/dead-letters/{event_id}",
        "Replay dead-letter event",
        "requester-a",
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        intent_fingerprint=FINGERPRINT,
    )

    assert result.approval_id == APPROVAL_ID
    assert result.tenant_id == str(TENANT_ID)
    assert result.status is ApprovalStatus.PENDING
    assert result.intent_fingerprint == FINGERPRINT
    assert connection.committed
    assert connection.closed
    assert any("set_config('platform.tenant_id'" in query for query, _ in connection.queries)
    assert any("INSERT INTO platform.action_approvals" in query for query, _ in connection.queries)
    assert any("INSERT INTO platform.action_approval_events" in query for query, _ in connection.queries)


def test_postgres_approval_consumption_is_bound_and_one_time():
    approved = approval_row("approved", approved_by="approver-b")
    consumed = approval_row(
        "consumed",
        approved_by="approver-b",
        consumed_at=datetime.now(UTC),
    )
    first = Connection(selected=approved, updated=consumed)
    second = Connection(selected=consumed)
    connections = iter((first, second))
    service = PostgresApprovalService(connection_factory=lambda: next(connections))

    service.require_approved_for(
        APPROVAL_ID,
        str(TENANT_ID),
        RUN_ID,
        "replay",
        "extensions://outbox/dead-letters/{event_id}",
        intent_fingerprint=FINGERPRINT,
    )
    assert first.committed
    assert any("status = 'consumed'" in query for query, _ in first.queries)

    with pytest.raises(PermissionError, match="approved human review"):
        service.require_approved_for(
            APPROVAL_ID,
            str(TENANT_ID),
            RUN_ID,
            "replay",
            "extensions://outbox/dead-letters/{event_id}",
            intent_fingerprint=FINGERPRINT,
        )
    assert not any("UPDATE platform.action_approvals" in query for query, _ in second.queries)


def test_postgres_approval_rejects_self_approval():
    connection = Connection(selected=approval_row())
    service = PostgresApprovalService(connection_factory=lambda: connection)

    with pytest.raises(PermissionError, match="requester cannot approve"):
        service.decide(
            APPROVAL_ID,
            True,
            str(TENANT_ID),
            approver_subject_id="requester-a",
            intent_fingerprint=FINGERPRINT,
        )
    assert not any("UPDATE platform.action_approvals" in query for query, _ in connection.queries)
    assert connection.rolled_back


def test_postgres_approval_fails_closed_when_rls_hides_foreign_tenant():
    connection = Connection(selected=None)
    service = PostgresApprovalService(connection_factory=lambda: connection)

    with pytest.raises(PermissionError):
        service.get(APPROVAL_ID, str(TENANT_ID))
    assert connection.committed


def test_postgres_approval_expiry_is_persisted():
    expired_at = datetime.now(UTC) - timedelta(seconds=1)
    pending = approval_row(expires_at=expired_at)
    expired = approval_row("expired", expires_at=expired_at)
    connection = Connection(selected=pending, updated=expired)
    service = PostgresApprovalService(connection_factory=lambda: connection)

    result = service.get(APPROVAL_ID, str(TENANT_ID))

    assert result.status is ApprovalStatus.EXPIRED
    assert connection.committed
    assert any("status = 'expired'" in query for query, _ in connection.queries)
