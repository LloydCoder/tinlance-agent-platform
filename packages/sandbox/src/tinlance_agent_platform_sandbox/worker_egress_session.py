"""Composition helper for request-bound worker network namespaces."""

from __future__ import annotations

from collections.abc import Callable

from tinlance_agent_platform_contracts import SandboxRequest

from .bubblewrap import SandboxLimits, SandboxProvider
from .executor import ProcessResult
from .policy import SandboxPolicy
from .service import SandboxUnavailable, execute_request, validate_request
from .worker_egress import WorkerEgressController, WorkerEgressSession
from .workspace_supervisor import WorkspaceLeaseSupervisor


def execute_network_request(
    request: SandboxRequest,
    policy: SandboxPolicy,
    provider: SandboxProvider,
    limits: SandboxLimits,
    *,
    controller: WorkerEgressController,
    policy_revision: str,
    lease_assertion: Callable[[SandboxRequest], bool],
    proxy_port: int = 3128,
    supervisor: WorkspaceLeaseSupervisor | None = None,
) -> ProcessResult:
    """Create, verify, use, and destroy one worker egress attachment.

    Validation happens before privileged namespace creation. The request-bound
    session supplies both the namespace and continuous kernel-boundary assertion
    to the existing sandbox service. Teardown is guaranteed on success and error.
    """
    if not request.network:
        raise SandboxUnavailable("network request composition requires request.network=True")
    validate_request(request, policy)
    with WorkerEgressSession(
        controller,
        request,
        policy_revision=policy_revision,
        proxy_port=proxy_port,
    ) as session:
        return execute_request(
            request,
            policy,
            provider,
            limits,
            lease_assertion=lease_assertion,
            egress_assertion=session.assert_active,
            network_namespace=session.network_namespace,
            supervisor=supervisor,
        )
