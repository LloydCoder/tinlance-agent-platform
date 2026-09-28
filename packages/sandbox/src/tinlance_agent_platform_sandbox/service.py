from tinlance_agent_platform_contracts import SandboxRequest

from .policy import SandboxPolicy


class SandboxUnavailable(RuntimeError):
    """Raised when a governed sandbox cannot be provided."""


def validate_request(
    request: SandboxRequest,
    policy: SandboxPolicy,
) -> None:
    policy.validate(request)
    if not request.allowed_paths:
        raise SandboxUnavailable("no isolated workspace path was supplied")
