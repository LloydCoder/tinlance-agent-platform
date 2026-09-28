from pathlib import Path
from uuid import uuid4

import pytest

from tinlance_agent_platform_contracts import (
    DataClass,
    ExecutionLimits,
    ExecutionRequest,
    RiskTier,
)
from tinlance_agent_platform_sandbox import DockerSandbox


def make_request(
    workspace: Path,
    command: tuple[str, ...],
    network: bool = False,
) -> ExecutionRequest:
    return ExecutionRequest(
        "1",
        uuid4(),
        uuid4(),
        "actor",
        "execute",
        str(workspace),
        command,
        RiskTier.LOW,
        DataClass.INTERNAL,
        ExecutionLimits(10, 256, 10, 32),
        None,
        network,
    )


@pytest.mark.integration
def test_sandbox_workspace_and_network_boundary(tmp_path: Path) -> None:
    marker = tmp_path / "marker"
    result = DockerSandbox().execute(
        make_request(
            tmp_path,
            ("sh", "-c", "echo ok > /workspace/marker"),
        )
    )

    assert result.exit_code == 0
    assert marker.read_text().strip() == "ok"
    assert result.trajectory_ref.endswith(str(result.execution_id))
    assert result.evidence_ref.endswith(str(result.execution_id))

    network = DockerSandbox().execute(
        make_request(
            tmp_path,
            (
                "python",
                "-c",
                "import socket; socket.create_connection(('1.1.1.1', 53), 1)",
            ),
        )
    )
    assert network.exit_code != 0


@pytest.mark.integration
def test_sandbox_timeout_cleans_execution(tmp_path: Path) -> None:
    with pytest.raises(TimeoutError):
        DockerSandbox().execute(
            make_request(
                tmp_path,
                ("python", "-c", "import time; time.sleep(30)"),
            )
        )
