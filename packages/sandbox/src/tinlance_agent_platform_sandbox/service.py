from collections.abc import Callable

from tinlance_agent_platform_contracts import SandboxRequest

from .bubblewrap import SandboxLimits, SandboxProvider
from .executor import ProcessResult
from .policy import SandboxPolicy
from .workspace_supervisor import WorkspaceLeaseSupervisor


class SandboxUnavailable(RuntimeError):
    """Raised when a governed sandbox cannot be provided."""


def validate_request(request: SandboxRequest, policy: SandboxPolicy) -> None:
    if not request.allowed_paths:
        raise SandboxUnavailable("no isolated workspace path was supplied")
    policy.validate(request)


def build_command(
    request: SandboxRequest,
    policy: SandboxPolicy,
    provider: SandboxProvider,
    limits: SandboxLimits,
) -> list[str]:
    validate_request(request, policy)
    return provider.command(list(request.command), limits, request.allowed_paths)


def execute_request(
    request: SandboxRequest,
    policy: SandboxPolicy,
    provider: SandboxProvider,
    limits: SandboxLimits,
    *,
    lease_assertion: Callable[[SandboxRequest], bool],
    supervisor: WorkspaceLeaseSupervisor | None = None,
) -> ProcessResult:
    """Execute a policy-approved command under a continuously asserted workspace lease.

    The lease assertion is supplied by the Platform composition layer, which binds
    the tenant-scoped durable lease store and exact fencing token. The sandbox
    package does not own or reconstruct that authority. The caller must bind the
    exact request tenant/workspace and fencing token into this assertion.
    """
    validate_request(request, policy)
    effective_timeout = min(limits.timeout_seconds, int(request.timeout_seconds))
    if effective_timeout < 1:
        raise SandboxUnavailable("sandbox timeout is below the executor's one-second minimum")
    effective_limits = SandboxLimits(
        timeout_seconds=effective_timeout,
        max_output_bytes=limits.max_output_bytes,
        max_memory_bytes=limits.max_memory_bytes,
        max_processes=limits.max_processes,
    )
    command = provider.command(list(request.command), effective_limits, request.allowed_paths)
    def assert_request_lease() -> bool:
        return lease_assertion(request)

    return (supervisor or WorkspaceLeaseSupervisor()).execute(
        assert_request_lease,
        command,
        cwd=request.allowed_paths[0],
        limits=effective_limits,
    )
