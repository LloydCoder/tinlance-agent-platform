"""Minimal fail-closed policy engine for M0."""

from tinlance_agent_platform_contracts import (
    CapabilityRequest,
    Decision,
    PolicyDecision,
    RiskTier,
)


def evaluate(request: CapabilityRequest) -> PolicyDecision:
    if request.risk is RiskTier.PROHIBITED:
        return PolicyDecision(
            Decision.DENY,
            "m0-risk",
            "1",
            "prohibited risk tier",
            request.risk,
        )
    if request.risk in {RiskTier.HIGH, RiskTier.CRITICAL}:
        return PolicyDecision(
            Decision.REQUIRE_APPROVAL,
            "m0-risk",
            "1",
            "elevated risk requires explicit approval",
            request.risk,
            True,
        )
    return PolicyDecision(
        Decision.ALLOW,
        "m0-risk",
        "1",
        "risk tier permits execution",
        request.risk,
    )
