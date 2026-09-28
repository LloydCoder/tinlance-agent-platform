from dataclasses import dataclass
from pathlib import PurePosixPath
from shutil import which
from typing import Protocol


@dataclass(frozen=True, slots=True)
class SandboxLimits:
    timeout_seconds: int = 30
    max_output_bytes: int = 1_000_000


class SandboxProvider(Protocol):
    def command(
        self, argv: list[str], limits: SandboxLimits, workspace_paths: tuple[str, ...] = ()
    ) -> list[str]: ...


class BubblewrapProvider:
    def __init__(self, binary: str = "bwrap") -> None:
        self.binary = binary

    def available(self) -> bool:
        return which(self.binary) is not None

    def command(
        self, argv: list[str], limits: SandboxLimits, workspace_paths: tuple[str, ...] = ()
    ) -> list[str]:
        if not argv or limits.timeout_seconds < 1 or limits.max_output_bytes < 1:
            raise ValueError("invalid sandbox request")
        if not self.available():
            raise RuntimeError("bubblewrap sandbox provider is unavailable")
        for path in workspace_paths:
            parsed = PurePosixPath(path)
            if not parsed.is_absolute() or ".." in parsed.parts or path == "/":
                raise PermissionError("invalid workspace path")
        command = [
            self.binary,
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/bin",
            "/bin",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
        ]
        for path in workspace_paths:
            command.extend(("--bind", path, path))
        command.extend(("--chdir", workspace_paths[0] if workspace_paths else "/tmp", "--", *argv))
        return command
