import re
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
    return provider.command(
        list(request.command), limits, request.allowed_paths, network=request.network
    )


def execute_request(
    request: SandboxRequest,
    policy: SandboxPolicy,
    provider: SandboxProvider,
    limits: SandboxLimits,
    *,
    lease_assertion: Callable[[SandboxRequest], bool],
    egress_assertion: Callable[[SandboxRequest], bool] | None = None,
    network_namespace: str | None = None,
    supervisor: WorkspaceLeaseSupervisor | None = None,
) -> ProcessResult:
    """Execute a command only while its workspace lease and egress boundary remain valid.

    The Platform composition layer supplies the tenant-scoped durable lease
    assertion and, for network-enabled requests, an egress assertion bound to the
    exact tenant, workspace, run, policy revision and worker network attachment.
    The sandbox package does not create or infer either authority. The executor
    rechecks the combined assertion throughout process execution and kills the
    process group if either authority is lost.
    """
    validate_request(request, policy)
    if request.network and not callable(egress_assertion):
        raise SandboxUnavailable(
            "network-enabled sandbox execution requires a verified egress boundary assertion"
        )
    if egress_assertion is not None and not callable(egress_assertion):
        raise TypeError("egress_assertion must be callable")
    if request.network:
        if not isinstance(network_namespace, str) or not re.fullmatch(
            r"tln-[0-9a-f]{10}", network_namespace
        ):
            raise SandboxUnavailable(
                "network-enabled sandbox execution requires an owned worker network namespace"
            )
    elif network_namespace is not None:
        raise SandboxUnavailable("non-network sandbox execution cannot select a worker network namespace")

    effective_timeout = min(limits.timeout_seconds, int(request.timeout_seconds))
    if effective_timeout < 1:
        raise SandboxUnavailable("sandbox timeout is below the executor's one-second minimum")
    effective_limits = SandboxLimits(
        timeout_seconds=effective_timeout,
        max_output_bytes=limits.max_output_bytes,
        max_memory_bytes=limits.max_memory_bytes,
        max_processes=limits.max_processes,
    )
    command = provider.command(
        list(request.command), effective_limits, request.allowed_paths, network=request.network
    )
    if request.network:
        command = ["ip", "netns", "exec", network_namespace, *command]

    def assert_request_authority() -> bool:
        if lease_assertion(request) is not True:
            return False
        return not request.network or (
            egress_assertion is not None and egress_assertion(request) is True
        )

    return (supervisor or WorkspaceLeaseSupervisor()).execute(
        assert_request_authority,
        command,
        cwd=request.allowed_paths[0],
        limits=effective_limits,
    )
