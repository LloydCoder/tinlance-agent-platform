from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from tinlance_agent_platform_approvals import PostgresApprovalService
from tinlance_agent_platform_contracts import ApprovalRequest, ApprovalStatus

ROOT = Path(__file__).resolve().parents[1]
TENANT_ID = UUID("00000000-0000-0000-0000-000000000091")
RUN_ID = UUID("40000000-0000-0000-0000-000000000091")
APPROVAL_ID = UUID("50000000-0000-0000-0000-000000000091")
FINGERPRINT = "a" * 64


class Cursor:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class Connection:
    def __init__(self, *, row=None, consume=True, fail_on=None):
        self.row = row or (
            APPROVAL_ID,
            TENANT_ID,
            RUN_ID,
            "invoice.refund",
            "invoice:123",
            "refund requested by account owner",
            "requester-a",
            "approved",
            {"source": "unit-test"},
            datetime.now(UTC) + timedelta(minutes=5),
            FINGERPRINT,
            "approver-b",
            None,
            None,
        )
        self.consume = consume
        self.fail_on = fail_on
        self.queries = []
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def execute(self, query, params=()):
        self.queries.append((query, params))
        if self.fail_on and self.fail_on in query:
            raise RuntimeError("simulated database failure")
        if "set_config('platform.tenant_id'" in query:
            return Cursor((params[0],))
        if "platform.request_approval" in query:
            return Cursor((params[0],))
        if "platform.decide_approval" in query:
            return Cursor(("approved",))
        if "platform.expire_approval_if_due" in query:
            return Cursor((False,))
        if "platform.consume_approval" in query:
            return Cursor((self.consume,))
        if "FROM platform.approvals" in query:
            return Cursor(self.row)
        return Cursor(None)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def service(connection):
    return PostgresApprovalService(connection_factory=lambda: connection)


def test_postgres_approval_request_persists_and_rehydrates_tenant_bound_contract() -> None:
    connection = Connection()
    approval = service(connection).request(
        str(TENANT_ID),
        RUN_ID,
        "invoice.refund",
        "invoice:123",
        "refund requested by account owner",
        "requester-a",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
        intent_fingerprint=FINGERPRINT,
    )

    assert isinstance(approval, ApprovalRequest)
    assert approval.approval_id == APPROVAL_ID
    assert approval.tenant_id == str(TENANT_ID)
    assert approval.run_id == RUN_ID
    assert approval.status is ApprovalStatus.APPROVED
    assert approval.approved_by == "approver-b"
    assert connection.queries[0][0].startswith("SELECT set_config('platform.tenant_id'")
    assert "platform.request_approval" in connection.queries[1][0]
    assert connection.committed is True
    assert connection.closed is True


def test_postgres_approval_decision_is_transactional_and_records_approver() -> None:
    connection = Connection()
    approval = service(connection).decide(
        APPROVAL_ID,
        True,
        str(TENANT_ID),
        approver_subject_id="approver-b",
        intent_fingerprint=FINGERPRINT,
    )

    assert approval.status is ApprovalStatus.APPROVED
    assert approval.approved_by == "approver-b"
    assert "platform.decide_approval" in connection.queries[1][0]
    assert connection.committed is True


def test_postgres_approval_verifier_consumes_exact_intent_once() -> None:
    connection = Connection(consume=True)
    service(connection).require_approved_for(
        APPROVAL_ID,
        str(TENANT_ID),
        RUN_ID,
        "invoice.refund",
        "invoice:123",
        intent_fingerprint=FINGERPRINT,
    )

    assert "platform.consume_approval" in connection.queries[1][0]
    assert connection.queries[1][1] == (
        TENANT_ID,
        APPROVAL_ID,
        RUN_ID,
        "invoice.refund",
        "invoice:123",
        FINGERPRINT,
    )
    assert connection.committed is True
    assert connection.closed is True


def test_postgres_approval_verifier_fails_closed_when_not_consumed() -> None:
    connection = Connection(consume=False)
    with pytest.raises(PermissionError, match="approved human review"):
        service(connection).require_approved_for(
            APPROVAL_ID,
            str(TENANT_ID),
            RUN_ID,
            "invoice.refund",
            "invoice:123",
            intent_fingerprint=FINGERPRINT,
        )
    assert connection.rolled_back is True
    assert connection.closed is True


def test_postgres_approval_get_expires_before_reading() -> None:
    connection = Connection()
    approval = service(connection).get(APPROVAL_ID, str(TENANT_ID))

    assert approval.status is ApprovalStatus.APPROVED
    assert "platform.expire_approval_if_due" in connection.queries[1][0]
    assert "FROM platform.approvals" in connection.queries[2][0]


def test_postgres_approval_rejects_invalid_tenant_and_unbounded_intent() -> None:
    connection = Connection()
    approvals = service(connection)
    with pytest.raises(ValueError, match="UUID tenant"):
        approvals.get(APPROVAL_ID, "tenant-a")
    with pytest.raises(ValueError, match="intent fingerprint"):
        approvals.request(
            str(TENANT_ID),
            RUN_ID,
            "invoice.refund",
            "invoice:123",
            "reason",
            "requester-a",
            intent_fingerprint="not-a-fingerprint",
        )
    assert connection.queries == []


def test_postgres_approval_rejects_naive_expiry() -> None:
    connection = Connection()
    with pytest.raises(ValueError, match="timezone-aware"):
        service(connection).request(
            str(TENANT_ID),
            RUN_ID,
            "invoice.refund",
            "invoice:123",
            "reason",
            "requester-a",
            expires_at=datetime.now(),
        )
    assert connection.queries == []


def test_postgres_approval_rolls_back_and_closes_on_database_failure() -> None:
    connection = Connection(fail_on="platform.request_approval")
    with pytest.raises(RuntimeError, match="simulated database failure"):
        service(connection).request(
            str(TENANT_ID),
            RUN_ID,
            "invoice.refund",
            "invoice:123",
            "reason",
            "requester-a",
        )
    assert connection.rolled_back is True
    assert connection.committed is False
    assert connection.closed is True


def test_postgres_approval_requires_caller_owned_transaction() -> None:
    connection = Connection()
    connection.autocommit = True
    with pytest.raises(RuntimeError, match="caller-owned transaction"):
        service(connection).get(APPROVAL_ID, str(TENANT_ID))
    assert connection.queries == []


def test_approval_migration_has_tenant_rls_expiry_and_append_only_audit() -> None:
    migration = (ROOT / "database/migrations/012_durable_approval_lifecycle.sql").read_text(
        encoding="utf-8"
    )
    for required in (
        "platform.approval_events",
        "platform.request_approval",
        "platform.decide_approval",
        "platform.consume_approval",
        "platform.expire_approval_if_due",
        "FOR UPDATE",
        "ENABLE ROW LEVEL SECURITY",
        "FORCE ROW LEVEL SECURITY",
        "REVOKE UPDATE, DELETE, TRUNCATE",
        "intent_fingerprint",
        "consumed_at",
    ):
        assert required.lower() in migration.lower()
