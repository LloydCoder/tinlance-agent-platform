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
