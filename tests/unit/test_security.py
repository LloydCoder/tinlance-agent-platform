from uuid import uuid4

import pytest

from tinlance_agent_platform_authorization import authorize
from tinlance_agent_platform_contracts import (
    AgentIdentity,
    CapabilityRequest,
    DataClass,
    Decision,
    Principal,
    RequestContext,
    Reversibility,
    RiskTier,
)
from tinlance_agent_platform_policy import evaluate
from tinlance_agent_platform_tenancy import child_context


def make_request(risk: RiskTier = RiskTier.LOW) -> CapabilityRequest:
    return CapabilityRequest(
        action="read",
        resource="document",
        capabilities=frozenset({"document:read"}),
        risk=risk,
        reversibility=Reversibility.REVERSIBLE,
        data_class=DataClass.INTERNAL,
        blast_radius="single-resource",
    )


def test_context_rejects_mismatched_principal() -> None:
    principal = Principal("owner", "human", "tenant-a")
    with pytest.raises(ValueError, match="tenants"):
        RequestContext("req", "tenant-b", principal, "test")


def test_prohibited_cannot_be_authorized() -> None:
    principal = Principal(
        "owner",
        "human",
        "tenant-a",
        scopes=frozenset({"document:read"}),
    )
    context = RequestContext("req", "tenant-a", principal, "test")
    decision = authorize(context, make_request(RiskTier.PROHIBITED))
    assert decision.decision is Decision.DENY


def test_high_risk_requires_approval() -> None:
    assert evaluate(make_request(RiskTier.HIGH)).decision is Decision.REQUIRE_APPROVAL


def test_child_context_cannot_cross_tenant() -> None:
    parent = RequestContext("p", "tenant-a", Principal("a", "human", "tenant-a"), "test")
    child = RequestContext("c", "tenant-b", Principal("b", "agent", "tenant-b"), "test")
    with pytest.raises(PermissionError):
        child_context(parent, child)


def test_agent_identity_is_versioned_and_tenant_scoped() -> None:
    identity = AgentIdentity(
        uuid4(),
        "tenant-a",
        "research",
        "1.0.0",
        "owner",
        "default",
        "standard",
        "test",
    )
    assert identity.version == "1.0.0"
