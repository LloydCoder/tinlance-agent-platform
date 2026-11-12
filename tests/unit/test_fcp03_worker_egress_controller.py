from __future__ import annotations

import hashlib
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

    def __call__(
        self,
        argv: list[str],
        *,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((argv, input_text))
        if argv == ["ip", "netns", "list"]:
            return subprocess.CompletedProcess(argv, 0, self.existing_namespaces, "")
        if argv[:3] == ["ip", "netns", "add"]:
            self.existing_namespaces += f"{argv[3]} (id: 1)\\n"
        if argv[:3] == ["ip", "netns", "del"]:
            self.existing_namespaces = "\\n".join(
                line
                for line in self.existing_namespaces.splitlines()
                if line.split() and line.split()[0] != argv[3]
            )
        if argv[:3] == ["ip", "link", "add"]:
            self.existing_links.add(argv[3])
        if argv[:3] == ["ip", "link", "del"]:
            self.existing_links.discard(argv[3])
        if argv[:3] == ["ip", "link", "show"]:
            name = argv[-1]
            if name in self.existing_links:
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 1, "", 'Cannot find device "missing"')
        if argv[-2:] == ["list", "ruleset"]:
            return subprocess.CompletedProcess(argv, 0, self.nft_result, "")
        if argv[-3:] == ["nft", "-f", "-"]:
            if self.fail_nft:
                return subprocess.CompletedProcess(argv, 1, "", "nft rejected policy")
            self.nft_result = input_text or ""
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
    nft_calls = [input_text for argv, input_text in runner.calls if argv[-3:] == ["nft", "-f", "-"]]
    assert len(nft_calls) == 1
    ruleset = nft_calls[0] or ""
    assert "policy drop" in ruleset
    assert f"tcp dport {attachment.proxy_port} accept" in ruleset
    assert "udp dport 53 accept" in ruleset
    assert "tcp dport 53 accept" in ruleset
    assert "forward" in ruleset
    route_commands = [
        argv
        for argv, _ in runner.calls
        if argv[:3] == ["ip", "netns", "exec"] and "route" in argv and "add" in argv
    ]
    assert not route_commands


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
    namespace = "tln-" + hashlib.sha256(b"worker-a").hexdigest()[:10]
    runner.existing_namespaces = f"{namespace} (id: 42)"
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


def test_existing_attachment_is_reused_only_while_policy_and_kernel_state_match(
    tmp_path: Path,
) -> None:
    runner = FakeRunner()
    controller = WorkerEgressController(
        state_dir=tmp_path / "state",
        runner=runner,
        require_root=False,
    )
    first = controller.create("worker-a", policy_revision="policy-7", proxy_port=3128)

    second = controller.create("worker-a", policy_revision="policy-7", proxy_port=3128)

    assert second == first
    assert sum(argv[:3] == ["ip", "netns", "add"] for argv, _ in runner.calls) == 1
    with pytest.raises(EgressBoundaryConflict, match="different egress attachment"):
        controller.create("worker-a", policy_revision="policy-8", proxy_port=3128)


def test_is_ready_fails_closed_when_nftables_policy_drifts(tmp_path: Path) -> None:
    runner = FakeRunner()
    controller = WorkerEgressController(
        state_dir=tmp_path / "state",
        runner=runner,
        require_root=False,
    )
    attachment = controller.create("worker-a", policy_revision="policy-7", proxy_port=3128)
    runner.nft_result = "table inet tinlance_egress { chain output { policy accept; } }"

    assert controller.is_ready(attachment) is False


def test_destroy_removes_only_the_owned_namespace_veth_and_state(tmp_path: Path) -> None:
    runner = FakeRunner()
    state_dir = tmp_path / "state"
    controller = WorkerEgressController(
        state_dir=state_dir,
        runner=runner,
        require_root=False,
    )
    attachment = controller.create("worker-a", policy_revision="policy-7", proxy_port=3128)

    controller.destroy("worker-a")

    assert not list(state_dir.glob("*.json"))
    assert attachment.namespace not in runner.existing_namespaces
    assert attachment.host_interface not in runner.existing_links
