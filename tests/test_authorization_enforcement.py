from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from tinlance_agent_platform_execution import (
    ExecutionErrorCode,
    ExecutionFailure,
    ExecutionRequest,
    GovernedExecutionService,
)

TENANT = "tenant-authz"
RUN_ID = UUID("00000000-0000-0000-0000-000000000401")
AGENT_ID = UUID("00000000-0000-0000-0000-000000000402")


class ApprovalStub:
    def __init__(self, *, error: bool = False) -> None:
        self.error = error
        self.calls: list[tuple[object, ...]] = []

    def validate_approved_for(self, *args: object, **kwargs: object) -> None:
        self.calls.append((*args, kwargs))
        if self.error:
            raise PermissionError("approval binding mismatch")


def request() -> ExecutionRequest:
    return ExecutionRequest(
        request_id="request-authz",
        idempotency_key="idem-authz",
        tenant_id=TENANT,
        principal_id="subject-authz",
        agent_id=AGENT_ID,
        run_id=RUN_ID,
        capability_id="capability.write",
        capability_version="1",
        tool_name="example.write",
        tool_version="1",
        action="write",
        resource="resource/1",
        input={"safe": True},
        requested_timeout_seconds=5,
        approval_id=uuid4(),
    )


def service_with(approvals: ApprovalStub) -> GovernedExecutionService:
    service = object.__new__(GovernedExecutionService)
    service.approvals = approvals
    return service


def test_bound_approval_is_checked_against_intent() -> None:
    approvals = ApprovalStub()
    service = service_with(approvals)
    req = request()
    service._require_bound_approval(req)
    assert approvals.calls[0][0] == req.approval_id
    assert approvals.calls[0][1] == TENANT
    assert approvals.calls[0][2] == RUN_ID
    assert approvals.calls[0][3] == req.action
    assert approvals.calls[0][4] == req.resource
    assert approvals.calls[0][5]["intent_fingerprint"] == req.fingerprint


def test_unbound_approval_fails_closed() -> None:
    approvals = ApprovalStub(error=True)
    service = service_with(approvals)
    with pytest.raises(ExecutionFailure) as exc_info:
        service._require_bound_approval(request())
    assert getattr(exc_info.value, "code", None) is ExecutionErrorCode.APPROVAL_BINDING_MISMATCH
