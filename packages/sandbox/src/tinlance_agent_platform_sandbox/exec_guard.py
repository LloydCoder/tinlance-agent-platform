"""Linux exec guard for thread-safe, parent-death-contained sandbox launches."""

from __future__ import annotations

import argparse
import ctypes
import os
import resource
import signal
import sys
from collections.abc import Sequence

_LIBC = ctypes.CDLL(None, use_errno=True)
_PRCTL = _LIBC.prctl
_PRCTL.argtypes = [
    ctypes.c_int,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
]
_PRCTL.restype = ctypes.c_int
_PR_SET_PDEATHSIG = 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent-pid", type=int, required=True)
    parser.add_argument("--cpu-seconds", type=int, required=True)
    parser.add_argument("--memory-bytes", type=int, required=True)
    parser.add_argument("--file-size-bytes", type=int, required=True)
    parser.add_argument("--max-processes", type=int, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def _apply_resource_limits(
    *,
    cpu_seconds: int,
    memory_bytes: int,
    file_size_bytes: int,
    max_processes: int,
) -> None:
    """Apply per-process limits without constraining virtual address reservations.

    RLIMIT_AS is incompatible with browsers and runtimes that reserve large sparse
    virtual address ranges. RLIMIT_DATA constrains data-segment/heap allocations
    (including eligible anonymous mmap allocations on supported Linux kernels).
    Production deployments must additionally enforce aggregate resident memory
    with a delegated cgroup-v2 memory.max boundary.
    """
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
    resource.setrlimit(resource.RLIMIT_DATA, (memory_bytes, memory_bytes))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_size_bytes, file_size_bytes))
    resource.setrlimit(resource.RLIMIT_NPROC, (max_processes, max_processes))


def main(argv: Sequence[str] | None = None) -> int:
    """Apply limits and parent-death containment, then replace this process."""
    args = _parser().parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    limits = (
        args.parent_pid,
        args.cpu_seconds,
        args.memory_bytes,
        args.file_size_bytes,
        args.max_processes,
    )
    if not command or any(value <= 0 for value in limits):
        _parser().error("positive limits, parent PID and a command are required")
    if not sys.platform.startswith("linux"):
        raise RuntimeError("sandbox exec guard requires Linux")

    if _PRCTL(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    # prctl cannot signal a child whose parent died before installation.
    if os.getppid() != args.parent_pid:
        os.kill(os.getpid(), signal.SIGKILL)

    _apply_resource_limits(
        cpu_seconds=args.cpu_seconds,
        memory_bytes=args.memory_bytes,
        file_size_bytes=args.file_size_bytes,
        max_processes=args.max_processes,
    )
    os.execvpe(command[0], command, os.environ.copy())
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
