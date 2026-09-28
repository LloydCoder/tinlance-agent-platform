"""Deterministic, fail-closed risk policy."""

from tinlance_agent_platform_contracts import (
    CapabilityRequest,
    DataClass,
    Decision,
    PolicyDecision,
    RiskTier,
    Reversibility,
)


def evaluate(request: CapabilityRequest) -> PolicyDecision:
    if request.risk is RiskTier.PROHIBITED or request.data_class is DataClass.SECRET:
        return PolicyDecision(
            Decision.DENY, "enterprise-risk", "2", "prohibited capability", request.risk
        )
    needs_approval = (
        request.risk in {RiskTier.HIGH, RiskTier.CRITICAL}
        or request.reversibility is Reversibility.IRREVERSIBLE
        or request.data_class in {DataClass.SENSITIVE, DataClass.RESTRICTED}
        or request.blast_radius != "single-resource"
    )
    if needs_approval:
        return PolicyDecision(
            Decision.REQUIRE_APPROVAL,
            "enterprise-risk",
            "2",
            "capability requires explicit human approval",
            request.risk,
            True,
        )
    return PolicyDecision(
        Decision.ALLOW,
        "enterprise-risk",
        "2",
        "capability satisfies deterministic risk policy",
        request.risk,
    )
