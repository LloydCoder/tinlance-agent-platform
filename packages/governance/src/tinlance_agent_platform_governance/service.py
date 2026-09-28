from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID


@dataclass(frozen=True, slots=True)
class CapabilityGrant:
    tenant_id: str
    agent_id: UUID
    capability: str
    resource: str
    expires_at: datetime | None = None

    def active(self, now: datetime | None = None) -> bool:
        return self.expires_at is None or self.expires_at > (now or datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class ApprovalBinding:
    approval_id: UUID
    tenant_id: str
    run_id: UUID
    capability: str
    resource: str
    expires_at: datetime

    def matches(self, tenant_id: str, run_id: UUID, capability: str, resource: str) -> bool:
        return (
            self.tenant_id == tenant_id
            and self.run_id == run_id
            and self.capability == capability
            and self.resource == resource
            and self.expires_at > datetime.now(UTC)
        )


class GovernanceService:
    def __init__(self) -> None:
        self._grants: list[CapabilityGrant] = []
        self._stopped: set[str] = set()

    def grant(self, grant: CapabilityGrant) -> None:
        if not grant.tenant_id or not grant.capability or not grant.resource:
            raise ValueError("complete capability grant required")
        self._grants.append(grant)

    def stop_tenant(self, tenant_id: str) -> None:
        if not tenant_id:
            raise ValueError("tenant is required")
        self._stopped.add(tenant_id)

    def authorize(self, tenant_id: str, agent_id: UUID, capability: str, resource: str) -> bool:
        if tenant_id in self._stopped:
            return False
        return any(
            g.tenant_id == tenant_id
            and g.agent_id == agent_id
            and g.capability == capability
            and g.resource == resource
            and g.active()
            for g in self._grants
        )
