from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class Delegation:
    delegation_id: UUID
    tenant_id: str
    parent_agent_id: UUID
    child_agent_id: UUID
    capabilities: frozenset[str]
    active: bool = True


class DelegationService:
    def __init__(self) -> None:
        self._delegations: dict[UUID, Delegation] = {}

    def delegate(
        self,
        tenant_id: str,
        parent_agent_id: UUID,
        child_agent_id: UUID,
        parent_capabilities: frozenset[str],
        requested_capabilities: frozenset[str],
    ) -> Delegation:
        if not requested_capabilities <= parent_capabilities:
            raise PermissionError("child authority cannot exceed parent authority")
        delegation = Delegation(
            uuid4(), tenant_id, parent_agent_id, child_agent_id, requested_capabilities
        )
        self._delegations[delegation.delegation_id] = delegation
        return delegation

    def revoke(self, tenant_id: str, delegation_id: UUID) -> None:
        delegation = self._delegations.get(delegation_id)
        if delegation is None or delegation.tenant_id != tenant_id:
            raise PermissionError("delegation is not owned by tenant")
        self._delegations[delegation_id] = Delegation(
            delegation.delegation_id,
            delegation.tenant_id,
            delegation.parent_agent_id,
            delegation.child_agent_id,
            delegation.capabilities,
            False,
        )

    def active(self, tenant_id: str, delegation_id: UUID) -> Delegation:
        delegation = self._delegations.get(delegation_id)
        if delegation is None or delegation.tenant_id != tenant_id or not delegation.active:
            raise PermissionError("delegation is inactive or cross-tenant")
        return delegation
