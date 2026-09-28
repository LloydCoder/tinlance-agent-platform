"""Tenant propagation rules."""

from tinlance_agent_platform_contracts import RequestContext
from tinlance_agent_platform_kernel import assert_child_tenant

def child_context(parent: RequestContext, child: RequestContext) -> RequestContext:
    assert_child_tenant(parent, child)
    return child
