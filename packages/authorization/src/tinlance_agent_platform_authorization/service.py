"""Deny-by-default capability authorization."""

from tinlance_agent_platform_contracts import CapabilityRequest, Decision, PolicyDecision, RequestContext
from tinlance_agent_platform_kernel import assert_authority_boundary

def authorize(context: RequestContext, request: CapabilityRequest) -> PolicyDecision:
    try:
        context.assert_tenant(context.principal.tenant_id)
        assert_authority_boundary(request, context.principal)
    except PermissionError as exc:
        return PolicyDecision(Decision.DENY, "kernel-deny", "1", str(exc), request.risk)
    return PolicyDecision(
        Decision.ALLOW,
        "scope-match",
        "1",
        "requested capabilities are within principal scopes",
        request.risk,
    )
