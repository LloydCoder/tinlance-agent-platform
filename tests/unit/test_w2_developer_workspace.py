from __future__ import annotations

from pathlib import Path

from scripts.benchmark_gvisor import (
    build_docker_command,
    build_w2_developer_workspace_payload,
)


def test_w2_developer_workspace_runs_git_python_and_node_acceptance_contract() -> None:
    payload = build_w2_developer_workspace_payload()
    fixture = (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "w2-developer-workspace"
        / "run-workspace.sh"
    )
    script = fixture.read_text(encoding="utf-8")
    dockerfile = fixture.with_name("Dockerfile").read_text(encoding="utf-8")
    for marker in (
        "TINLANCE_W2_GIT_CLONE_OK",
        "TINLANCE_W2_PYTHON_EDIT_OK",
        "TINLANCE_W2_PYTHON_BUILD_OK",
        "TINLANCE_W2_PYTHON_TESTS_OK",
        "TINLANCE_W2_NODE_EDIT_OK",
        "TINLANCE_W2_NODE_BUILD_OK",
        "TINLANCE_W2_NODE_TESTS_OK",
        "TINLANCE_W2_WORKTREE_DIRTY_OK",
        "TINLANCE_W2_DEVELOPER_WORKSPACE_OK",
    ):
        assert marker in script or marker in payload
    assert " clone --no-hardlinks " in script
    assert "chown -R 65532:65532 /opt/tinlance-fixture" in dockerfile
    assert "mkdir -p /workspace" in dockerfile
    assert "python3 -m compileall" in script
    assert "python3 -m unittest" in script
    assert "node --check" in script
    assert "npm test" in script
    assert "w2-package-manifest.lock" in script
    assert "TINLANCE_W2_PACKAGE_MANIFEST_SHA256=" in script
    assert "/opt/tinlance-fixture/run-workspace.sh" in payload


def test_w2_image_build_uses_an_immutable_ubuntu_snapshot_and_package_manifest() -> None:
    fixture_root = Path(__file__).resolve().parents[1]
    fixture = fixture_root / "fixtures" / "w2-developer-workspace" / "Dockerfile"
    dockerfile = fixture.read_text(encoding="utf-8")
    assert "ARG APT_SNAPSHOT" in dockerfile
    assert '--snapshot="${APT_SNAPSHOT}" update' in dockerfile
    assert '--snapshot="${APT_SNAPSHOT}" install' in dockerfile
    assert "dpkg-query -W" in dockerfile
    assert "w2-package-manifest.lock" in dockerfile
    update_index = dockerfile.index('--snapshot="${APT_SNAPSHOT}" update')
    install_index = dockerfile.index('--snapshot="${APT_SNAPSHOT}" install')
    assert update_index < install_index
    assert "ca-certificates git python3 nodejs npm util-linux" in dockerfile
    assert "openssl=3.0.13-0ubuntu3.16" not in dockerfile
    assert "libssl3t64=3.0.13-0ubuntu3.16" not in dockerfile
    assert "Acquire::Retries=5" in dockerfile
    assert "APT::Update::Error-Mode=any" in dockerfile
    assert dockerfile.count("--snapshot=") == 2
    assert "ca-certificates=20260816ubuntu0.24.04.2" in dockerfile
    assert dockerfile.index("apt-get update") < dockerfile.index(
        '--snapshot="${APT_SNAPSHOT}" update'
    )


def test_w2_build_workflows_share_a_digest_pinned_base_and_snapshot() -> None:
    workflow_root = Path(__file__).resolve().parents[2] / ".github" / "workflows"
    base_digest = "ubuntu@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852"
    for name in (
        "persistent-computer-firecracker-w2.yml",
        "persistent-computer-gvisor-benchmark.yml",
        "persistent-computer-kata-benchmark.yml",
    ):
        workflow = (workflow_root / name).read_text(encoding="utf-8")
        assert base_digest in workflow
        assert "--build-arg APT_SNAPSHOT=20261106T000000Z" in workflow


def test_w2_developer_workspace_mount_is_bounded_and_unavailable_to_w1() -> None:
    image = "ubuntu@sha256:" + "a" * 64
    w1 = build_docker_command(image_digest=image, payload="true")
    w2 = build_docker_command(
        image_digest="sha256:" + "b" * 64,
        payload=build_w2_developer_workspace_payload(),
        workspace=True,
    )
    workspace_mount = "/workspace:rw,noexec,nosuid,nodev,size=128m,uid=65532,gid=65532,mode=0700"
    assert workspace_mount not in w1
    assert workspace_mount in w2
    assert "--network=none" in w2
    assert "--read-only" in w2
    assert "--cap-drop=ALL" in w2
    assert "--user=65532:65532" in w2
    assert "sha256:" + "b" * 64 in w2
