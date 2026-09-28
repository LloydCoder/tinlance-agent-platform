from uuid import UUID, uuid4

from tinlance_agent_platform_contracts import ApprovalRequest, ApprovalStatus


class ApprovalService:
    def __init__(self) -> None:
        self._items: dict[UUID, ApprovalRequest] = {}

    def request(
        self,
        tenant_id: str,
        run_id: UUID,
        action: str,
        resource: str,
        reason: str,
        requested_by: str,
    ) -> ApprovalRequest:
        item = ApprovalRequest(
            uuid4(),
            tenant_id,
            run_id,
            action,
            resource,
            reason,
            requested_by,
        )
        self._items[item.approval_id] = item
        return item

    def decide(self, approval_id: UUID, approved: bool, tenant_id: str) -> ApprovalRequest:
        current = self._items.get(approval_id)
        if current is None:
            raise KeyError("approval does not exist")
        if current.tenant_id != tenant_id:
            raise PermissionError("approval is owned by another tenant")
        if current.status is not ApprovalStatus.PENDING:
            raise ValueError("approval is no longer pending")
        status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
        updated = ApprovalRequest(
            current.approval_id,
            current.tenant_id,
            current.run_id,
            current.action,
            current.resource,
            current.reason,
            current.requested_by,
            status,
            current.metadata,
        )
        self._items[approval_id] = updated
        return updated

    def require_approved(self, approval_id: UUID) -> None:
        current = self._items.get(approval_id)
        if current is None or current.status is not ApprovalStatus.APPROVED:
            raise PermissionError("approved human review is required")

    def require_approved_for(
        self,
        approval_id: UUID,
        tenant_id: str,
        run_id: UUID,
        action: str,
        resource: str,
    ) -> None:
        current = self._items.get(approval_id)
        if current is None or current.status is not ApprovalStatus.APPROVED:
            raise PermissionError("approved human review is required")
        if (
            current.tenant_id != tenant_id
            or current.run_id != run_id
            or current.action != action
            or current.resource != resource
        ):
            raise PermissionError("approval does not bind to this action")
