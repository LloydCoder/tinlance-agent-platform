import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from tinlance_agent_platform_durability import WorkspaceLease
from tinlance_agent_platform_runtime import ExecutionTimeout, call_with_timeout
from tinlance_agent_platform_sandbox import SandboxExecutor, SandboxLimits, WorkspaceLeaseSupervisor


def test_model_deadline_is_hard() -> None:
    def slow() -> str:
        time.sleep(0.2)
        return "late"

    with pytest.raises(ExecutionTimeout):
        call_with_timeout(slow, 0.05)


def test_sandbox_executor_enforces_timeout(tmp_path: Path) -> None:
    result = SandboxExecutor().execute(
        ["/bin/sh", "-c", "sleep 2"],
        cwd=str(tmp_path),
        limits=SandboxLimits(timeout_seconds=1, max_output_bytes=4096),
    )
    assert result.timed_out is True
    assert result.exit_code != 0


def test_sandbox_executor_captures_output(tmp_path: Path) -> None:
    result = SandboxExecutor().execute(
        ["/bin/sh", "-c", "printf 'ok'"],
        cwd=str(tmp_path),
        limits=SandboxLimits(timeout_seconds=2, max_output_bytes=4096),
    )
    assert result.timed_out is False
    assert result.exit_code == 0
    assert result.stdout == "ok"


def test_sandbox_executor_enforces_combined_stdout_stderr_output_limit(tmp_path: Path) -> None:
    limit = 128
    result = SandboxExecutor().execute(
        [
            "/usr/bin/python3",
            "-c",
            "import sys; sys.stdout.write('o' * 96); sys.stderr.write('e' * 96)",
        ],
        cwd=str(tmp_path),
        limits=SandboxLimits(timeout_seconds=2, max_output_bytes=limit),
    )

    assert result.exit_code == 0
    assert len(result.stdout.encode("utf-8")) + len(result.stderr.encode("utf-8")) <= limit
    assert result.stdout == "o" * 96
    assert result.stderr == "e" * 32


def test_sandbox_executor_rejects_an_inactive_workspace_lease_before_spawn(tmp_path: Path) -> None:
    from tinlance_agent_platform_sandbox import WorkspaceLeaseLost

    marker = tmp_path / "must-not-exist"
    command = [
        "/usr/bin/python3",
        "-c",
        f"from pathlib import Path; Path({str(marker)!r}).touch()",
    ]
    with pytest.raises(WorkspaceLeaseLost):
        SandboxExecutor().execute(
            command,
            cwd=str(tmp_path),
            limits=SandboxLimits(timeout_seconds=3, max_output_bytes=4096),
            lease_assertion=lambda: False,
        )

    assert not marker.exists()


def test_sandbox_executor_kills_descendants_after_process_leader_exits_on_lease_loss(
    tmp_path: Path,
) -> None:
    from tinlance_agent_platform_sandbox import WorkspaceLeaseLost

    marker = tmp_path / "descendant-survived"
    child_code = f"import time; time.sleep(0.6); open({str(marker)!r}, 'w').write('late')"
    parent_code = f"import subprocess,sys; subprocess.Popen([sys.executable, '-c', {child_code!r}])"
    checks = 0

    def lease_is_active() -> bool:
        nonlocal checks
        checks += 1
        return checks < 3

    with pytest.raises(WorkspaceLeaseLost):
        SandboxExecutor().execute(
            ["/usr/bin/python3", "-c", parent_code],
            cwd=str(tmp_path),
            limits=SandboxLimits(timeout_seconds=3, max_output_bytes=4096),
            lease_assertion=lease_is_active,
        )

    time.sleep(0.8)
    assert not marker.exists(), "lease loss must kill descendants even after the group leader exits"


def test_sandbox_executor_kills_process_group_when_workspace_lease_is_lost(tmp_path: Path) -> None:
    from tinlance_agent_platform_sandbox import WorkspaceLeaseLost

    started = tmp_path / "started"
    finished = tmp_path / "finished"
    checks = 0

    def lease_is_active() -> bool:
        nonlocal checks
        checks += 1
        return checks < 3

    command = (
        "from pathlib import Path; import time; "
        f"Path({str(started)!r}).touch(); time.sleep(5); "
        f"Path({str(finished)!r}).touch()"
    )
    with pytest.raises(WorkspaceLeaseLost):
        SandboxExecutor().execute(
            ["/usr/bin/python3", "-c", command],
            cwd=str(tmp_path),
            limits=SandboxLimits(timeout_seconds=10, max_output_bytes=4096),
            lease_assertion=lease_is_active,
        )

    assert started.exists()
    assert not finished.exists()
    assert checks >= 3


class ActiveWorkspaceLeaseStore:
    def __init__(self, active: bool = True) -> None:
        self.active = active
        self.assertions = 0

    def assert_active(self, lease: object) -> bool:
        self.assertions += 1
        return self.active


def test_workspace_lease_supervisor_binds_the_lease_store_to_each_command(tmp_path: Path) -> None:
    store = ActiveWorkspaceLeaseStore()
    supervisor = WorkspaceLeaseSupervisor(store)
    lease = WorkspaceLease(
        UUID("00000000-0000-0000-0000-000000000092"),
        UUID("20000000-0000-0000-0000-000000000092"),
        UUID("30000000-0000-0000-0000-000000000092"),
        "owner-a",
        "worker-a",
        1,
        datetime.now(UTC) + timedelta(minutes=10),
    )
    result = supervisor.execute(
        lease,
        ["/usr/bin/python3", "-c", "print('fenced')"],
        cwd=str(tmp_path),
        limits=SandboxLimits(timeout_seconds=3, max_output_bytes=4096),
    )

    assert result.exit_code == 0
    assert result.stdout.strip() == "fenced"
    assert store.assertions >= 2


def test_workspace_lease_supervisor_fails_closed_when_the_lease_store_is_unavailable(
    tmp_path: Path,
) -> None:
    class UnavailableLeaseStore:
        def assert_active(self, lease: object) -> bool:
            raise RuntimeError("database unavailable")

    marker = tmp_path / "must-not-exist"
    supervisor = WorkspaceLeaseSupervisor(UnavailableLeaseStore())
    command = [
        "/usr/bin/python3",
        "-c",
        f"from pathlib import Path; Path({str(marker)!r}).touch()",
    ]

    from tinlance_agent_platform_sandbox import WorkspaceLeaseLost

    with pytest.raises(WorkspaceLeaseLost):
        supervisor.execute(
            WorkspaceLease(
                UUID("00000000-0000-0000-0000-000000000093"),
                UUID("20000000-0000-0000-0000-000000000093"),
                UUID("30000000-0000-0000-0000-000000000093"),
                "owner-a",
                "worker-a",
                1,
                datetime.now(UTC) + timedelta(minutes=10),
            ),
            command,
            cwd=str(tmp_path),
            limits=SandboxLimits(timeout_seconds=3, max_output_bytes=4096),
        )

    assert not marker.exists()
