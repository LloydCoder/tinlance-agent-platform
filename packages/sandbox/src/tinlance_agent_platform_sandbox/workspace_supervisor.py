"""Trusted supervisor for durable, fenced workspace command execution."""

from __future__ import annotations

from typing import Protocol

from tinlance_agent_platform_durability import WorkspaceLease

from .bubblewrap import SandboxLimits
from .executor import ProcessResult, SandboxExecutor


class WorkspaceLeaseStore(Protocol):
    """Minimal durable lease authority required by the workspace supervisor."""

    def assert_active(self, lease: object) -> bool: ...


class WorkspaceLeaseSupervisor:
    """Bind sandbox command execution to a durable Platform workspace lease.

    The lease store is queried before launch and throughout execution by the
    SandboxExecutor. A database outage, expiry, revocation or fencing-token
    mismatch is fail-closed and causes the command process group to be killed.
    """

    def __init__(
        self,
        lease_store: WorkspaceLeaseStore,
        *,
        executor: SandboxExecutor | None = None,
    ) -> None:
        self._lease_store = lease_store
        self._executor = executor or SandboxExecutor()

    def execute(
        self,
        lease: WorkspaceLease,
        argv: list[str],
        *,
        cwd: str,
        limits: SandboxLimits,
    ) -> ProcessResult:
        def assertion() -> bool:
            return self._lease_store.assert_active(lease)

        return self._executor.execute(
            argv,
            cwd=cwd,
            limits=limits,
            lease_assertion=assertion,
        )
