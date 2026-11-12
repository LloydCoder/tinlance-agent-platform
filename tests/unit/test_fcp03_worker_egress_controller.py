from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tinlance_agent_platform_sandbox.worker_egress import (
    EgressBoundaryConflict,
    EgressBoundaryNotReady,
    WorkerEgressController,
)


class FakeRunner:
    def __init__(self, *, nft_result: str = "") -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.nft_result = nft_result
        self.fail_nft = False
        self.existing_namespaces = ""
        self.existing_links: set[str] = set()

    def __call__(self, argv: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        self.calls.append((argv, input_text))
        if argv == ["ip", "netns", "list"]:
            return subprocess.CompletedProcess(argv, 0, self.existing_namespaces, "")
        if argv[:3] == ["ip", "link", "show"]:
            name = argv[-1]
            return subprocess.CompletedProcess(argv, 0 if name in self.existing_links else 1, "", "")
        if argv[-3:] == ["nft", "list", "table"] or argv[-4:-1] == ["nft", "list", "table"]:
            return subprocess.CompletedProcess(argv, 0, self.nft_result, "")
        if argv[-3:] == ["nft", "-f", "-"]:
            if self.fail_nft:
                return subprocess.CompletedProcess(argv, 1, "", "nft rejected policy")
        return subprocess.CompletedProcess(argv, 0, "", "")


def test_create_installs_atomic_default_deny_policy_without_default_route(tmp_path: Path) -> None:
    runner = FakeRunner()
    controller = WorkerEgressController(
        state_dir=tmp_path / "state",
        runner=runner,
        require_root=False,
    )

    attachment = controller.create("worker-a", policy_revision="policy-7", proxy_port=3128)

    assert attachment.worker_id == "worker-a"
    assert attachment.policy_revision == "policy-7"
    nft_calls = [
        input_text
        for argv, input_text in runner.calls
        if argv[-3:] == ["nft", "-f", "-"]
    ]
    assert len(nft_calls) == 1
    ruleset = nft_calls[0] or ""
    assert "policy drop" in ruleset
    assert f"tcp dport {attachment.proxy_port} accept" in ruleset
    assert "udp dport 53 accept" in ruleset
    assert "tcp dport 53 accept" in ruleset
    assert "forward" in ruleset
    assert not any(argv[:3] == ["ip", "netns", "exec"] and "route" in argv for argv, _ in runner.calls)


def test_create_fails_closed_and_cleans_owned_objects_when_nftables_rejects_policy(
    tmp_path: Path,
) -> None:
    runner = FakeRunner()
    runner.fail_nft = True
    controller = WorkerEgressController(
        state_dir=tmp_path / "state",
        runner=runner,
        require_root=False,
    )

    with pytest.raises(EgressBoundaryNotReady, match="nftables"):
        controller.create("worker-a", policy_revision="policy-7", proxy_port=3128)

    commands = [argv for argv, _ in runner.calls]
    assert any(argv[:3] == ["ip", "netns", "del"] for argv in commands)
    assert any(argv[:3] == ["ip", "link", "del"] for argv in commands)
    assert not list((tmp_path / "state").glob("*.json")) if (tmp_path / "state").exists() else True


def test_create_rejects_a_preexisting_namespace_without_ownership_metadata(
    tmp_path: Path,
) -> None:
    runner = FakeRunner()
    runner.existing_namespaces = "tln-deadbeef00 (id: 42)"
    controller = WorkerEgressController(
        state_dir=tmp_path / "state",
        runner=runner,
        require_root=False,
    )

    with pytest.raises(EgressBoundaryConflict, match="already exists"):
        controller.create("worker-a", policy_revision="policy-7", proxy_port=3128)

    assert not any(argv[:3] == ["ip", "netns", "del"] for argv, _ in runner.calls)


def test_create_rejects_symlinked_state_directory(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "state-link"
    link.symlink_to(target, target_is_directory=True)
    controller = WorkerEgressController(
        state_dir=link,
        runner=FakeRunner(),
        require_root=False,
    )

    with pytest.raises(EgressBoundaryNotReady, match="state directory"):
        controller.create("worker-a", policy_revision="policy-7", proxy_port=3128)
