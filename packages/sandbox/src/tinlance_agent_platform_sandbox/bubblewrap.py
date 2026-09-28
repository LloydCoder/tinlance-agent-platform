from dataclasses import dataclass
from os import environ
from shutil import which
from subprocess import CompletedProcess, TimeoutExpired, run
from time import monotonic
from typing import Protocol

from tinlance_agent_platform_contracts import ExecutionResult, SandboxRequest

@dataclass(frozen=True, slots=True)
class SandboxLimits:
    timeout_seconds: int = 30
    max_output_bytes: int = 1_000_000

class SandboxProvider(Protocol):
    def command(self, request: SandboxRequest, limits: SandboxLimits) -> list[str]: ...
    def execute(self, request: SandboxRequest, limits: SandboxLimits) -> ExecutionResult: ...

class BubblewrapProvider:
    def __init__(self, binary: str = "bwrap") -> None:
        self.binary = binary

    def available(self) -> bool:
        return which(self.binary) is not None

    def command(self, request: SandboxRequest, limits: SandboxLimits) -> list[str]:
        if not request.command or limits.timeout_seconds < 1 or limits.max_output_bytes < 1:
            raise ValueError("invalid sandbox request")
        if not self.available():
            raise RuntimeError("bubblewrap sandbox provider is unavailable")
        if request.timeout_seconds > limits.timeout_seconds:
            raise ValueError("request timeout exceeds provider limit")
        args = [self.binary, "--die-with-parent", "--new-session", "--unshare-all"]
        if not request.network:
            args.append("--unshare-net")
        args.extend(["--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"])
        for path in request.allowed_paths:
            args.extend(["--ro-bind", path, path])
        for path in request.writable_paths:
            args.extend(["--bind", path, path])
        if request.workspace_path:
            args.extend(["--bind", request.workspace_path, "/workspace", "--chdir", "/workspace"])
        else:
            args.extend(["--chdir", "/tmp"])
        args.extend(["--", *request.command])
        return args

    def execute(self, request: SandboxRequest, limits: SandboxLimits) -> ExecutionResult:
        argv = self.command(request, limits)
        started = monotonic()
        env = {key: value for key, value in environ.items() if key in request.environment_keys}
        try:
            completed: CompletedProcess[str] = run(argv, capture_output=True, text=True, timeout=request.timeout_seconds, check=False, env=env)
            return ExecutionResult(request.request_id, completed.returncode, completed.stdout[:limits.max_output_bytes], completed.stderr[:limits.max_output_bytes], monotonic() - started)
        except TimeoutExpired as exc:
            return ExecutionResult(request.request_id, 124, str(exc.stdout or "")[:limits.max_output_bytes], str(exc.stderr or "")[:limits.max_output_bytes], monotonic() - started)
