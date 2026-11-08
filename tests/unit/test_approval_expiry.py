from datetime import UTC, datetime, timedelta
from time import sleep
from uuid import uuid4

import pytest

from tinlance_agent_platform_approvals import ApprovalService


def test_expired_approval_fails_closed() -> None:
    service = ApprovalService()
    approval = service.request(
        "t1",
        uuid4(),
        "delete",
        "db:item",
        "reason",
        "agent",
        expires_at=datetime.now(UTC) + timedelta(seconds=0.5),
    )
    sleep(0.02)
    with pytest.raises(PermissionError):
        service.require_approved(approval.approval_id)


def test_approved_but_unconsumed_approval_expires():
    service = ApprovalService()
    approval = service.request(
        "t1",
        uuid4(),
        "replay",
        "extensions://outbox/dead-letters/{event_id}",
        "reason",
        "requester",
        expires_at=datetime.now(UTC) + timedelta(seconds=0.01),
        intent_fingerprint="a" * 64,
    )
    service.decide(
        approval.approval_id,
        True,
        "t1",
        approver_subject_id="approver",
        intent_fingerprint="a" * 64,
    )
    sleep(0.6)

    expired = service.get(approval.approval_id, "t1")

    assert expired.status.value == "expired"
    assert expired.approved_by == "approver"
