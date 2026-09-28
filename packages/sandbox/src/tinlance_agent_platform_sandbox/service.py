from tinlance_agent_platform_contracts import SandboxRequest

from .bubblewrap import SandboxLimits, SandboxProvider
from .policy import SandboxPolicy


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
