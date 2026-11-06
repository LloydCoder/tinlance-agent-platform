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
    assert "git clone" in script
    assert "python3 -m compileall" in script
    assert "python3 -m unittest" in script
    assert "node --check" in script
    assert "npm test" in script
    assert "/opt/tinlance-fixture/run-workspace.sh" in payload


def test_w2_developer_workspace_mount_is_bounded_and_unavailable_to_w1() -> None:
    image = "ubuntu@sha256:" + "a" * 64
    w1 = build_docker_command(image_digest=image, payload="true")
    w2 = build_docker_command(
        image_digest="sha256:" + "b" * 64,
        payload=build_w2_developer_workspace_payload(),
        workspace=True,
    )
    workspace_mount = (
        "/workspace:rw,noexec,nosuid,nodev,size=128m,"
        "uid=65532,gid=65532,mode=0700"
    )
    assert workspace_mount not in w1
    assert workspace_mount in w2
    assert "--network=none" in w2
    assert "--read-only" in w2
    assert "--cap-drop=ALL" in w2
    assert "--user=65532:65532" in w2
    assert "sha256:" + "b" * 64 in w2
