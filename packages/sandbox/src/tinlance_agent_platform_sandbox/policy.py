from dataclasses import dataclass
from pathlib import PurePosixPath

from tinlance_agent_platform_contracts import SandboxRequest


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    allowed_commands: frozenset[str]
    allowed_workspace_roots: tuple[str, ...] = ("/workspace",)
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
        if not request.allowed_paths:
            raise PermissionError("at least one isolated workspace path is required")
        roots = tuple(PurePosixPath(root) for root in self.allowed_workspace_roots)
        if not roots:
            raise PermissionError("sandbox workspace roots are not configured")
        for root in roots:
            if (
                not root.is_absolute()
                or ".." in root.parts
                or root
                in {
                    PurePosixPath("/"),
                    PurePosixPath("/etc"),
                    PurePosixPath("/proc"),
                    PurePosixPath("/sys"),
                    PurePosixPath("/dev"),
                }
            ):
                raise PermissionError("sandbox workspace roots are invalid")
        for raw_path in request.allowed_paths:
            path = PurePosixPath(raw_path)
            if not path.is_absolute() or ".." in path.parts:
                raise PermissionError("workspace paths must be absolute and traversal-free")
            if raw_path in {"/", "/etc", "/proc", "/sys", "/dev"}:
                raise PermissionError("sensitive host paths cannot be sandbox workspaces")
            if not any(path == root or root in path.parents for root in roots):
                raise PermissionError("workspace path is outside the approved sandbox roots")
        for key in request.environment_keys:
            if not key or "=" in key or "\x00" in key:
                raise PermissionError("invalid sandbox environment key")
