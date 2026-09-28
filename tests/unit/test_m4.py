from datetime import UTC, datetime, timedelta
from uuid import uuid4

from tinlance_agent_platform_governance import CapabilityGrant, GovernanceService


def test_capability_grant_is_exact_and_expiring() -> None:
    service = GovernanceService()
    agent = uuid4()
    grant = CapabilityGrant(
        "t1", agent, "read", "repo:a", datetime.now(UTC) + timedelta(minutes=1)
    )
    service.grant(grant)
    assert service.authorize("t1", agent, "read", "repo:a")
    assert not service.authorize("t1", agent, "write", "repo:a")


def test_emergency_stop_denies_even_granted_capability() -> None:
    service = GovernanceService()
    agent = uuid4()
    service.grant(CapabilityGrant("t1", agent, "read", "repo:a"))
    service.stop_tenant("t1")
    assert not service.authorize("t1", agent, "read", "repo:a")
