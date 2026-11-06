from __future__ import annotations

from scripts.benchmark_gvisor import (
    build_docker_command,
    build_w2_developer_workspace_payload,
)


def test_w2_developer_workspace_clones_edits_builds_and_tests_python_and_node_projects() -> None:
    payload = build_w2_developer_workspace_payload()
    for marker in (
        "TINLANCE_W2_GIT_CLONE_OK",
        "TINLANCE_W2_PYTHON_EDIT_OK",
        "TINLANCE_W2_PYTHON_TESTS_OK",
        "TINLANCE_W2_NODE_EDIT_OK",
        "TINLANCE_W2_NODE_TESTS_OK",
        "TINLANCE_W2_DEVELOPER_WORKSPACE_OK",
    ):
        assert marker in payload
    assert "git clone" in payload
    assert "python3" in payload
    assert "npm test" in payload


def test_w2_developer_workspace_mount_is_bounded_and_unavailable_to_w1() -> None:
    image = "ubuntu@sha256:" + "a" * 64
    w1 = build_docker_command(image_digest=image, payload="true")
    w2 = build_docker_command(
        image_digest=image,
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
