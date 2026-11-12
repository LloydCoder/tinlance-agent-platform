from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path
from uuid import UUID

import pytest

from tinlance_agent_platform_contracts import SandboxRequest
from tinlance_agent_platform_sandbox import (
    ProcessResult,
    SandboxLimits,
    SandboxPolicy,
    SandboxUnavailable,
    WorkerEgressController,
    WorkerEgressSession,
    execute_network_request,
)


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.namespaces: set[str] = set()
        self.links: set[str] = set()
        self.nft_result = ""

    def __call__(
        self,
        argv: list[str],
        *,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((argv, input_text))
        if argv == ["ip", "netns", "list"]:
            output = "\\n".join(sorted(self.namespaces))
            return subprocess.CompletedProcess(argv, 0, output, "")
        if argv[:3] == ["ip", "netns", "add"]:
            self.namespaces.add(argv[3])
        elif argv[:3] == ["ip", "netns", "del"]:
            self.namespaces.discard(argv[3])
        elif argv[:3] == ["ip", "link", "add"]:
            self.links.add(argv[3])
        elif argv[:3] == ["ip", "link", "del"]:
            self.links.discard(argv[3])
        elif argv[:3] == ["ip", "link", "show"]:
            if argv[-1] not in self.links:
                return subprocess.CompletedProcess(argv, 1, "", "Cannot find device")
        elif argv[-3:] == ["nft", "-f", "-"]:
            self.nft_result = input_text or ""
        elif argv[-2:] == ["list", "ruleset"]:
            return subprocess.CompletedProcess(argv, 0, self.nft_result, "")
        return subprocess.CompletedProcess(argv, 0, "", "")


class FakeProvider:
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


class FakeSupervisor:
    def __init__(self, *, fail: bool = False) -> None:
        self.argv: list[str] = []
        self.fail = fail

    def execute(
        self,
        assertion: Callable[[], bool],
        argv: list[str],
        *,
        cwd: str,
        limits: SandboxLimits,
    ) -> ProcessResult:
        assert assertion() is True
        self.argv = argv
        if self.fail:
            raise RuntimeError("simulated command failure")
        return ProcessResult(0, "network-work-complete", "")


def make_request(tmp_path: Path, *, network: bool = True) -> SandboxRequest:
    return SandboxRequest(
        UUID("00000000-0000-0000-0000-0000000000a1"),
        "tenant-a",
        UUID("40000000-0000-0000-0000-0000000000a1"),
        "workspace-a",
        ("/usr/bin/python3", "-c", "print('network-work')"),
        5,
        network=network,
        allowed_paths=(str(tmp_path),),
    )


def make_policy(tmp_path: Path) -> SandboxPolicy:
    return SandboxPolicy(
        allowed_commands=frozenset({"/usr/bin/python3"}),
        allowed_workspace_roots=(str(tmp_path),),
        allow_network=True,
    )


def test_network_execution_owns_and_tears_down_request_namespace(tmp_path: Path) -> None:
    request = make_request(tmp_path)
    runner = FakeRunner()
    state_dir = tmp_path / "state"
    controller = WorkerEgressController(
        state_dir=state_dir,
        runner=runner,
        require_root=False,
    )
    supervisor = FakeSupervisor()

    result = execute_network_request(
        request,
        make_policy(tmp_path),
        FakeProvider(),
        SandboxLimits(),
        controller=controller,
        policy_revision="policy-42",
        lease_assertion=lambda candidate: candidate is request,
        supervisor=supervisor,
    )

    assert result.stdout == "network-work-complete"
    assert supervisor.argv[:3] == ["ip", "netns", "exec"]
    assert not runner.namespaces
    assert not runner.links
    assert not list(state_dir.glob("*.json"))


def test_network_session_tears_down_after_execution_error(tmp_path: Path) -> None:
    request = make_request(tmp_path)
    runner = FakeRunner()
    state_dir = tmp_path / "state"
    controller = WorkerEgressController(
        state_dir=state_dir,
        runner=runner,
        require_root=False,
    )

    with pytest.raises(RuntimeError, match="simulated command failure"):
        execute_network_request(
            request,
            make_policy(tmp_path),
            FakeProvider(),
            SandboxLimits(),
            controller=controller,
            policy_revision="policy-42",
            lease_assertion=lambda candidate: candidate is request,
            supervisor=FakeSupervisor(fail=True),
        )

    assert not runner.namespaces
    assert not runner.links
    assert not list(state_dir.glob("*.json"))


def test_worker_egress_session_is_bound_to_exact_request_and_kernel_state(tmp_path: Path) -> None:
    request = make_request(tmp_path)
    other_request = make_request(tmp_path)
    runner = FakeRunner()
    controller = WorkerEgressController(
        state_dir=tmp_path / "state",
        runner=runner,
        require_root=False,
    )

    with WorkerEgressSession(
        controller,
        request,
        policy_revision="policy-42",
    ) as session:
        assert session.assert_active(request) is True
        assert session.assert_active(other_request) is False
        runner.nft_result = "table inet tinlance_egress { chain output { policy accept; } }"
        assert session.assert_active(request) is False


def test_network_execution_rejects_non_network_request_before_namespace_creation(
    tmp_path: Path,
) -> None:
    runner = FakeRunner()
    controller = WorkerEgressController(
        state_dir=tmp_path / "state",
        runner=runner,
        require_root=False,
    )

    with pytest.raises(SandboxUnavailable, match="network=True"):
        execute_network_request(
            make_request(tmp_path, network=False),
            make_policy(tmp_path),
            FakeProvider(),
            SandboxLimits(),
            controller=controller,
            policy_revision="policy-42",
            lease_assertion=lambda _: True,
            supervisor=FakeSupervisor(),
        )

    assert not runner.calls
