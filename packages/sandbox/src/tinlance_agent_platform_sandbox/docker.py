"""Docker baseline sandbox with explicit isolation and fail-closed behavior."""
import os
import shutil
import subprocess
from pathlib import Path
from uuid import uuid4

from tinlance_agent_platform_contracts import ExecutionRequest, ExecutionResultRef


class SandboxUnavailable(RuntimeError):
    """Raised when the required sandbox runtime is unavailable."""


class DockerSandbox:
    def __init__(self, image: str = "python:3.13-slim") -> None:
        self.image = image

    def execute(self, request: ExecutionRequest) -> ExecutionResultRef:
        docker = shutil.which("docker")
        workspace = Path(request.workspace).resolve()
        if docker is None:
            raise SandboxUnavailable("docker runtime unavailable; execution denied")
        if not workspace.is_dir():
            raise ValueError("workspace must be an existing directory")

        execution_id = uuid4()
        name = f"tap-sbx-{execution_id.hex}"
        network = "default" if request.allow_network else "none"
        env_args: list[str] = []

        for key in request.allowed_env:
            value = os.environ.get(key)
            if value is not None:
                env_args.extend(["-e", f"{key}={value}"])

        command = [
            docker,
            "run",
            "--rm",
            "--name",
            name,
            "--network",
            network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(request.limits.pids),
            "--memory",
            f"{request.limits.memory_mb}m",
            "--cpus",
            "1",
            "--ulimit",
            f"cpu={request.limits.cpu_seconds}",
            "-w",
            "/workspace",
            "-v",
            f"{workspace}:/workspace:rw",
            *env_args,
            self.image,
            *request.command,
        ]

        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=request.limits.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            subprocess.run(
                [docker, "rm", "-f", name],
                check=False,
                capture_output=True,
                text=True,
            )
            raise TimeoutError("sandbox execution timed out") from exc

        return ExecutionResultRef(
            execution_id,
            request.request_id,
            f"trajectory:{execution_id}",
            f"evidence:{execution_id}",
            completed.returncode,
        )
