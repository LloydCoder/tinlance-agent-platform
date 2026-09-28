from dataclasses import dataclass
from shutil import which
from typing import Protocol


@dataclass(frozen=True, slots=True)
class SandboxLimits:
    timeout_seconds: int = 30
    max_output_bytes: int = 1_000_000


class SandboxProvider(Protocol):
    def command(self, argv: list[str], limits: SandboxLimits) -> list[str]: ...


class BubblewrapProvider:
    def __init__(self, binary: str = "bwrap") -> None:
        self.binary = binary

    def available(self) -> bool:
        return which(self.binary) is not None

    def command(self, argv: list[str], limits: SandboxLimits) -> list[str]:
        if not argv or limits.timeout_seconds < 1 or limits.max_output_bytes < 1:
            raise ValueError("invalid sandbox request")
        if not self.available():
            raise RuntimeError("bubblewrap sandbox provider is unavailable")
        return [
            self.binary,
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/bin", "/bin",
            "--proc", "/proc",
            "--dev", "/dev",
            "--tmpfs", "/tmp",
            "--chdir", "/tmp",
            "--",
            *argv,
        ]
