"""Production-oriented process execution boundary for sandboxed commands."""

from __future__ import annotations

import os
import resource
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .bubblewrap import SandboxLimits


@dataclass(frozen=True, slots=True)
class ProcessResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


def _limit_process(limits: SandboxLimits) -> None:
    """Apply hard POSIX resource ceilings before the sandbox process starts."""
    cpu = max(1, int(limits.timeout_seconds))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
    memory = limits.max_memory_bytes
    resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    resource.setrlimit(resource.RLIMIT_FSIZE, (limits.max_output_bytes, limits.max_output_bytes))
    resource.setrlimit(resource.RLIMIT_NPROC, (limits.max_processes, limits.max_processes))


class SandboxExecutor:
    """Execute an already-policy-validated sandbox command with hard limits.

    The executor is POSIX-only by design. Unsupported hosts fail closed rather
    than silently dropping isolation or resource limits.
    """

    def execute(self, argv: list[str], *, cwd: str, limits: SandboxLimits) -> ProcessResult:
        if os.name != "posix":
            raise RuntimeError("production sandbox execution requires POSIX isolation")
        if not argv or not Path(cwd).is_absolute():
            raise ValueError("sandbox command and absolute cwd are required")
        if (
            limits.timeout_seconds < 1
            or limits.max_output_bytes < 1
            or limits.max_memory_bytes < 1
            or limits.max_processes < 1
        ):
            raise ValueError("invalid sandbox limits")

        with tempfile.TemporaryDirectory(prefix="tinlance-sandbox-") as tmp:
            stdout_path = Path(tmp) / "stdout"
            stderr_path = Path(tmp) / "stderr"
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                process = subprocess.Popen(
                    argv,
                    cwd=cwd,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    start_new_session=True,
                    close_fds=True,
                    preexec_fn=lambda: _limit_process(limits),
                )
                timed_out = False
                try:
                    process.wait(timeout=limits.timeout_seconds)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()

            stdout_data = stdout_path.read_bytes()[: limits.max_output_bytes]
            stderr_data = stderr_path.read_bytes()[: limits.max_output_bytes]
            return ProcessResult(
                process.returncode,
                stdout_data.decode("utf-8", errors="replace"),
                stderr_data.decode("utf-8", errors="replace"),
                timed_out,
            )
