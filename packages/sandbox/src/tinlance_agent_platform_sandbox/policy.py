from dataclasses import dataclass

from tinlance_agent_platform_contracts import SandboxRequest


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    allowed_commands: frozenset[str]
    allow_network: bool = False
    max_timeout_seconds: float = 300.0

    def validate(self, request: SandboxRequest) -> None:
        if not request.command:
            raise PermissionError("empty command is forbidden")
        if request.network and not self.allow_network:
            raise PermissionError("network access is forbidden by sandbox policy")
        if request.timeout_seconds <= 0 or request.timeout_seconds > self.max_timeout_seconds:
            raise PermissionError("sandbox timeout exceeds policy")
        if request.command[0] not in self.allowed_commands:
            raise PermissionError("command is not allowlisted")
