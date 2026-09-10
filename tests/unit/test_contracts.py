from uuid import uuid4

import pytest

from tinlance_agent_platform.contracts import (
    AgentIdentity,
    AutonomyLevel,
    DataClass,
    Principal,
    RequestContext,
    RiskTier,
)


def test_request_context_is_tenant_bound() -> None:
    principal = Principal(
        subject_id="agent-owner",
        principal_type="human",
        tenant_id="tenant-a",
    )
    context = RequestContext(
        request_id="req-1",
        tenant_id="tenant-a",
        principal=principal,
        environment="development",
    )

    context.assert_tenant("tenant-a")
    with pytest.raises(PermissionError):
        context.assert_tenant("tenant-b")


def test_agent_identity_is_versioned_and_tenant_scoped() -> None:
    identity = AgentIdentity(
        agent_id=uuid4(),
        tenant_id="tenant-a",
        agent_type="research",
        version="1.0.0",
        owner_subject_id="operator-1",
        policy_profile="default",
        trust_level="standard",
        environment="staging",
    )
    assert identity.version == "1.0.0"
    assert identity.tenant_id == "tenant-a"


def test_security_enums_have_explicit_wire_values() -> None:
    assert AutonomyLevel.HIGH_AUTONOMY.value == 7
    assert RiskTier.PROHIBITED.value == "prohibited"
    assert DataClass.SECRET.value == "secret"
