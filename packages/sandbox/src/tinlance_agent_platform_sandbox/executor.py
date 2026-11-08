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
from time import monotonic, sleep

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
    def _has_exited_without_reaping(process: subprocess.Popen[bytes]) -> bool:
        # WNOWAIT keeps the group leader's PID reserved until descendants are
        # terminated, preventing a reused process-group ID from being signalled.
        info = os.waitid(
            os.P_PID,
            process.pid,
            os.WEXITED | os.WNOHANG | os.WNOWAIT,
        )
        return info is not None and info.si_pid == process.pid

    @staticmethod
    def _kill_and_reap(process: subprocess.Popen[bytes]) -> None:
        # Signal the original process group before reaping its leader so the
        # process-group ID cannot be reused while cleanup is in progress.
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
        if not all(hasattr(os, name) for name in ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")):
            raise RuntimeError("safe process-group supervision requires waitid with WNOWAIT")
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
                group_cleaned = False
                try:
                    while True:
                        self._assert_lease(lease_assertion)
                        remaining = deadline - monotonic()
                        if remaining <= 0:
                            timed_out = True
                            self._kill_and_reap(process)
                            group_cleaned = True
                            break
                        if self._has_exited_without_reaping(process):
                            # The leader is still a zombie, keeping its process-group
                            # ID reserved while any detached descendants are killed.
                            self._kill_and_reap(process)
                            group_cleaned = True
                            break
                        sleep(min(self._LEASE_POLL_INTERVAL_SECONDS, remaining))

                    # Capture output only after every process in the command group is dead.
                    stdout_data = stdout_path.read_bytes()[: limits.max_output_bytes]
                    stderr_budget = max(0, limits.max_output_bytes - len(stdout_data))
                    stderr_data = stderr_path.read_bytes()[:stderr_budget]
                    # Recheck after output collection so a revoked lease cannot receive
                    # a result merely because the command completed before revocation.
                    self._assert_lease(lease_assertion)
                except BaseException:
                    if not group_cleaned:
                        self._kill_and_reap(process)
                    raise

            # max_output_bytes is an aggregate result budget across both streams.
            # Preserve stdout first, then use only the remaining budget for stderr.
            return ProcessResult(
                process.returncode,
                stdout_data.decode("utf-8", errors="replace"),
                stderr_data.decode("utf-8", errors="replace"),
                timed_out,
            )
