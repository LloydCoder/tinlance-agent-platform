"""Trusted supervisor for durable, fenced workspace command execution."""

from __future__ import annotations

from collections.abc import Callable

from .bubblewrap import SandboxLimits
from .executor import ProcessResult, SandboxExecutor


class WorkspaceLeaseSupervisor:
    """Bind each command to a caller-supplied durable Platform lease assertion.

    The Platform composition layer binds the lease and tenant-scoped lease store
    into the assertion. The sandbox package deliberately does not depend on the
    durability package. Assertion failures, expiry, revocation and fencing-token
    mismatches are fail-closed and cause the process group to be killed and reaped.
    """

    def __init__(self, *, executor: SandboxExecutor | None = None) -> None:
        self._executor = executor or SandboxExecutor()

    def execute(
        self,
        lease_assertion: Callable[[], bool],
        argv: list[str],
        *,
        cwd: str,
        limits: SandboxLimits,
    ) -> ProcessResult:
        if not callable(lease_assertion):
            raise TypeError("lease_assertion must be callable")
        return self._executor.execute(
            argv,
            cwd=cwd,
            limits=limits,
            lease_assertion=lease_assertion,
        )
