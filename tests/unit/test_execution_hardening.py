import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from tinlance_agent_platform_contracts import SandboxRequest
from tinlance_agent_platform_durability import WorkspaceLease
from tinlance_agent_platform_runtime import ExecutionTimeout, call_with_timeout
from tinlance_agent_platform_sandbox import (
    BubblewrapProvider,
    SandboxExecutor,
    SandboxLimits,
    SandboxPolicy,
    WorkspaceLeaseSupervisor,
    execute_request,
)


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
        lease_assertion=lambda: True,
    )
    assert result.timed_out is True
    assert result.exit_code != 0


def test_sandbox_executor_captures_output(tmp_path: Path) -> None:
    result = SandboxExecutor().execute(
        ["/bin/sh", "-c", "printf 'ok'"],
        cwd=str(tmp_path),
        limits=SandboxLimits(timeout_seconds=2, max_output_bytes=4096),
        lease_assertion=lambda: True,
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
        lease_assertion=lambda: True,
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


def test_sandbox_executor_terminates_background_descendants_when_leader_exits(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "background-descendant-survived"
    child_code = f"import time; time.sleep(0.6); open({str(marker)!r}, 'w').write('late')"
    parent_code = f"import subprocess,sys; subprocess.Popen([sys.executable, '-c', {child_code!r}])"

    result = SandboxExecutor().execute(
        ["/usr/bin/python3", "-c", parent_code],
        cwd=str(tmp_path),
        limits=SandboxLimits(timeout_seconds=3, max_output_bytes=4096),
        lease_assertion=lambda: True,
    )

    assert result.exit_code == 0
    time.sleep(0.8)
    assert not marker.exists(), "a completed command must not leave background descendants running"


def test_sandbox_executor_kills_command_when_supervisor_process_dies(tmp_path: Path) -> None:
    started = tmp_path / "supervisor-crash-started"
    finished = tmp_path / "supervisor-crash-finished"
    command = (
        "from pathlib import Path; import time; "
        f"Path({str(started)!r}).touch(); time.sleep(3); "
        f"Path({str(finished)!r}).touch()"
    )
    supervisor_code = f"""
from tinlance_agent_platform_sandbox import SandboxExecutor, SandboxLimits
SandboxExecutor().execute(
    ["/usr/bin/python3", "-c", {command!r}],
    cwd={str(tmp_path)!r},
    limits=SandboxLimits(timeout_seconds=8, max_output_bytes=4096),
    lease_assertion=lambda: True,
)
"""
    supervisor = subprocess.Popen([sys.executable, "-c", supervisor_code], cwd=str(tmp_path))
    deadline = time.monotonic() + 5
    while not started.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert started.exists(), "supervised command did not start"
    supervisor.kill()
    supervisor.wait(timeout=5)

    time.sleep(3.5)
    assert not finished.exists(), "command survived an unexpected supervisor process exit"


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
    supervisor = WorkspaceLeaseSupervisor()
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
        lambda: store.assert_active(lease),
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
    store = UnavailableLeaseStore()
    lease = WorkspaceLease(
        UUID("00000000-0000-0000-0000-000000000093"),
        UUID("20000000-0000-0000-0000-000000000093"),
        UUID("30000000-0000-0000-0000-000000000093"),
        "owner-a",
        "worker-a",
        1,
        datetime.now(UTC) + timedelta(minutes=10),
    )
    supervisor = WorkspaceLeaseSupervisor()
    command = [
        "/usr/bin/python3",
        "-c",
        f"from pathlib import Path; Path({str(marker)!r}).touch()",
    ]

    from tinlance_agent_platform_sandbox import WorkspaceLeaseLost

    with pytest.raises(WorkspaceLeaseLost):
        supervisor.execute(
            lambda: store.assert_active(lease),
            command,
            cwd=str(tmp_path),
            limits=SandboxLimits(timeout_seconds=3, max_output_bytes=4096),
        )

    assert not marker.exists()


def test_sandbox_service_executes_commands_through_the_lease_supervisor(tmp_path: Path) -> None:
    request = SandboxRequest(
        UUID("00000000-0000-0000-0000-000000000094"),
        "tenant-a",
        UUID("40000000-0000-0000-0000-000000000094"),
        "workspace-a",
        ("/usr/bin/python3", "-c", "print('governed-workspace')"),
        3,
        network=True,
        allowed_paths=(str(tmp_path),),
    )
    policy = SandboxPolicy(
        allowed_commands=frozenset({"/usr/bin/python3"}),
        allowed_workspace_roots=(str(tmp_path),),
        allow_network=True,
    )

    class PassthroughProvider:
        def command(
            self,
            argv: list[str],
            limits: SandboxLimits,
            workspace_paths: tuple[str, ...] = (),
            *,
            network: bool = False,
        ) -> list[str]:
            assert network is True
            return argv

    assertions = 0

    def active_lease(candidate: SandboxRequest) -> bool:
        nonlocal assertions
        assertions += 1
        assert candidate is request
        return True

    result = execute_request(
        request,
        policy,
        PassthroughProvider(),
        SandboxLimits(timeout_seconds=5, max_output_bytes=4096),
        lease_assertion=active_lease,
    )

    assert result.exit_code == 0
    assert result.stdout.strip() == "governed-workspace"
    assert assertions >= 2


def test_bubblewrap_provider_shares_only_the_callers_network_namespace_when_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = BubblewrapProvider()
    monkeypatch.setattr(provider, "available", lambda: True)

    command = provider.command(
        ["/usr/bin/python3", "-c", "print('ok')"],
        SandboxLimits(),
        ("/workspace",),
        network=True,
    )

    assert "--unshare-all" in command
    assert "--share-net" in command
    assert command.index("--share-net") > command.index("--unshare-all")


def test_bubblewrap_provider_unshares_network_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = BubblewrapProvider()
    monkeypatch.setattr(provider, "available", lambda: True)

    command = provider.command(
        ["/usr/bin/python3", "-c", "print('ok')"],
        SandboxLimits(),
        ("/workspace",),
    )

    assert "--unshare-all" in command
    assert "--share-net" not in command


def test_sandbox_executor_avoids_preexec_fn_in_multithreaded_parent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from tinlance_agent_platform_sandbox import executor as executor_module

    original_popen = subprocess.Popen
    launch: dict[str, object] = {}

    def recording_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        launch.update(kwargs)
        return original_popen(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(executor_module.subprocess, "Popen", recording_popen)
    result = SandboxExecutor().execute(
        ["/usr/bin/python3", "-c", "print('thread-safe-launch')"],
        cwd=str(tmp_path),
        limits=SandboxLimits(timeout_seconds=3, max_output_bytes=4096),
        lease_assertion=lambda: True,
    )

    assert result.exit_code == 0
    assert result.stdout.strip() == "thread-safe-launch"
    assert launch.get("preexec_fn") is None
    command = launch.get("args")
    assert isinstance(command, list)
    assert command[1:3] == ["-m", "tinlance_agent_platform_sandbox.exec_guard"]
