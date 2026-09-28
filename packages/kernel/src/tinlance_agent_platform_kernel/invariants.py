"""Security invariants independent of providers and frameworks."""

from tinlance_agent_platform_contracts import (
    CapabilityRequest,
    Principal,
    RequestContext,
    RiskTier,
)


def assert_authority_boundary(request: CapabilityRequest, principal: Principal) -> None:
    if not request.capabilities:
        raise PermissionError("capability set is empty")
    if not principal.scopes:
        raise PermissionError("principal has no authority scopes")
    if not request.capabilities.issubset(principal.scopes):
        raise PermissionError("requested capability exceeds principal authority")
    if request.risk is RiskTier.PROHIBITED:
        raise PermissionError("prohibited actions are never executable")


def assert_child_tenant(parent: RequestContext, child: RequestContext) -> None:
    if child.tenant_id != parent.tenant_id:
        raise PermissionError("child context cannot change tenant")
    if child.principal.tenant_id != parent.tenant_id:
        raise PermissionError("child principal cannot change tenant")
