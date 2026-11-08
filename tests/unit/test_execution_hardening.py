import time
from pathlib import Path

import pytest

from tinlance_agent_platform_runtime import ExecutionTimeout, call_with_timeout
from tinlance_agent_platform_sandbox import SandboxExecutor, SandboxLimits


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
