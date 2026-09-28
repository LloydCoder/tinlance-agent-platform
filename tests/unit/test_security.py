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
from tinlance_agent_platform_identity import validate_principal
from tinlance_agent_platform_policy import evaluate
from tinlance_agent_platform_tenancy import child_context


def make_request(
    risk: RiskTier = RiskTier.LOW,
    *,
    reversibility: Reversibility = Reversibility.REVERSIBLE,
    data_class: DataClass = DataClass.INTERNAL,
    blast_radius: str = "single-resource",
) -> CapabilityRequest:
    return CapabilityRequest(
        action="read", resource="document", capabilities=frozenset({"document:read"}),
        risk=risk, reversibility=reversibility, data_class=data_class, blast_radius=blast_radius,
    )


def test_identity_rejects_untrimmed_identifiers() -> None:
    with pytest.raises(ValueError):
        validate_principal(Principal(" owner", "human", "tenant-a"))


def test_prohibited_and_secret_capabilities_cannot_be_authorized() -> None:
    principal = Principal("owner", "human", "tenant-a", scopes=frozenset({"document:read"}))
    context = RequestContext("req", "tenant-a", principal, "test")
    assert authorize(context, make_request(RiskTier.PROHIBITED)).decision is Decision.DENY
    assert evaluate(make_request(data_class=DataClass.SECRET)).decision is Decision.DENY


def test_high_risk_and_irreversible_actions_require_approval() -> None:
    assert evaluate(make_request(RiskTier.HIGH)).decision is Decision.REQUIRE_APPROVAL
    decision = evaluate(make_request(reversibility=Reversibility.IRREVERSIBLE))
    assert decision.decision is Decision.REQUIRE_APPROVAL


def test_child_context_cannot_cross_tenant() -> None:
    parent = RequestContext("p", "tenant-a", Principal("a", "human", "tenant-a"), "test")
    child = RequestContext("c", "tenant-b", Principal("b", "agent", "tenant-b"), "test")
    with pytest.raises(PermissionError):
        child_context(parent, child)


def test_agent_identity_is_versioned_and_tenant_scoped() -> None:
    identity = AgentIdentity(
        uuid4(), "tenant-a", "research", "1.0.0", "owner", "default", "standard", "test"
    )
    assert identity.version == "1.0.0"
