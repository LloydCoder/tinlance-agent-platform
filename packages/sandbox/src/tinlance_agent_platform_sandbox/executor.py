"""Production-oriented process execution boundary for sandboxed commands."""

from __future__ import annotations

import os
import resource
import signal
import subprocess
import tempfile
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from time import monotonic

from .bubblewrap import SandboxLimits


class WorkspaceLeaseLost(RuntimeError):
    """Raised when a persistent workspace loses its current fencing authority."""


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
    """Execute a policy-validated sandbox command with hard limits.

    Persistent workspace commands must provide a lease assertion. The process is
    launched in its own session/process group; lease loss kills and reaps that
    entire group before control returns to the caller.
    """

    _LEASE_POLL_INTERVAL_SECONDS = 0.25

    @staticmethod
    def _assert_lease(lease_assertion: Callable[[], bool]) -> None:
        try:
            active = lease_assertion()
        except Exception as exc:
            raise WorkspaceLeaseLost(
                "workspace lease authority is unavailable; command execution fails closed"
            ) from exc
        if active is not True:
            raise WorkspaceLeaseLost("workspace lease is expired, revoked, or fenced")

    @staticmethod
    def _kill_and_reap(process: subprocess.Popen[bytes]) -> None:
        # The group leader may have exited while descendants still run. Always
        # signal the original process group; checking only poll() would orphan
        # those descendants after a fast parent exit.
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()

    def execute(
        self,
        argv: list[str],
        *,
        cwd: str,
        limits: SandboxLimits,
        lease_assertion: Callable[[], bool],
    ) -> ProcessResult:
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

        # Check before creating any process or crossing the command boundary.
        self._assert_lease(lease_assertion)

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
                deadline = monotonic() + limits.timeout_seconds
                try:
                    while True:
                        self._assert_lease(lease_assertion)
                        remaining = deadline - monotonic()
                        if remaining <= 0:
                            timed_out = True
                            self._kill_and_reap(process)
                            break
                        try:
                            process.wait(timeout=min(self._LEASE_POLL_INTERVAL_SECONDS, remaining))
                            break
                        except subprocess.TimeoutExpired:
                            continue
                    # Do not return output to a caller whose lease expired at completion.
                    self._assert_lease(lease_assertion)
                except WorkspaceLeaseLost:
                    self._kill_and_reap(process)
                    raise

            # max_output_bytes is an aggregate result budget across both streams.
            # Preserve stdout first, then use only the remaining budget for stderr.
            stdout_data = stdout_path.read_bytes()[: limits.max_output_bytes]
            stderr_budget = max(0, limits.max_output_bytes - len(stdout_data))
            stderr_data = stderr_path.read_bytes()[:stderr_budget]
            return ProcessResult(
                process.returncode,
                stdout_data.decode("utf-8", errors="replace"),
                stderr_data.decode("utf-8", errors="replace"),
                timed_out,
            )
