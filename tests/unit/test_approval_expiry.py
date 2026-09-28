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
        expires_at=datetime.now(UTC) + timedelta(seconds=0.01),
    )
    sleep(0.02)
    with pytest.raises(PermissionError):
        service.require_approved(approval.approval_id)
