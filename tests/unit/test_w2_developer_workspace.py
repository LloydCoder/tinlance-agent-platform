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
    node_package = (fixture.parent / "node" / "package.json").read_text(encoding="utf-8")
    node_app = (fixture.parent / "node" / "src" / "app.js").read_text(encoding="utf-8")
    local_package = (
        fixture.parent / "node" / "vendor" / "w2-fixture-package" / "package.json"
    ).read_text(encoding="utf-8")
    for marker in (
        "TINLANCE_W2_GIT_CLONE_OK",
        "TINLANCE_W2_PYTHON_EDIT_OK",
        "TINLANCE_W2_PYTHON_BUILD_OK",
        "TINLANCE_W2_PYTHON_TESTS_OK",
        "TINLANCE_W2_NODE_EDIT_OK",
        "TINLANCE_W2_NODE_BUILD_OK",
        "TINLANCE_W2_NODE_TESTS_OK",
        "TINLANCE_W2_NPM_INSTALL_OK",
        "TINLANCE_W2_WORKTREE_DIRTY_OK",
        "TINLANCE_W2_DEVELOPER_WORKSPACE_OK",
    ):
        assert marker in script or marker in payload
    assert " clone --no-hardlinks " in script
    assert "git config --global --add safe.directory /opt/tinlance-fixture/.git" in script
    assert "export HOME=/tmp" in script
    assert "chown -R 65532:65532 /opt/tinlance-fixture" in dockerfile
    assert "mkdir -p /workspace" in dockerfile
    assert "python3 -m compileall" in script
    assert "python3 -m unittest" in script
    assert "node --check" in script
    assert "npm ci --offline --ignore-scripts --no-audit --no-fund" in script
    assert script.index("npm ci --offline") < script.index("npm test")
    assert "TINLANCE_W2_NPM_INSTALL_OK" in script
    assert "TINLANCE_W2_NPM_LOCK_SHA256=" in script
    assert '"@tinlance/w2-fixture-package": "file:vendor/w2-fixture-package"' in node_package
    assert '"name": "@tinlance/w2-fixture-package"' in local_package
    assert 'from "@tinlance/w2-fixture-package"' in node_app
    assert "npm test" in script
    assert "w2-package-manifest.lock" in script
    assert "TINLANCE_W2_PACKAGE_MANIFEST_SHA256=" in script
    assert "/opt/tinlance-fixture/run-workspace.sh" in payload


def test_w2_image_build_uses_an_immutable_ubuntu_snapshot_and_package_manifest() -> None:
    fixture_root = Path(__file__).resolve().parents[1]
    fixture = fixture_root / "fixtures" / "w2-developer-workspace" / "Dockerfile"
    dockerfile = fixture.read_text(encoding="utf-8")
    assert "ARG APT_SNAPSHOT" in dockerfile
    base_image = (
        "ARG BASE_IMAGE=ubuntu@"
        "sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852"
    )
    assert base_image in dockerfile
    assert "https://snapshot.ubuntu.com/ubuntu/${APT_SNAPSHOT}" in dockerfile
    assert 'grep -c "^URIs: https://snapshot.ubuntu.com/ubuntu/${APT_SNAPSHOT}$"' in dockerfile
    assert dockerfile.count("update " + chr(92)) == 2
    assert dockerfile.count("install --yes --no-install-recommends") == 2
    assert "--snapshot=" not in dockerfile
    assert "dpkg-query -W" in dockerfile
    assert (
        "npm install --package-lock-only --offline --ignore-scripts --no-audit --no-fund"
        in dockerfile
    )
    assert "w2-package-manifest.lock" in dockerfile
    secret_mount = (
        "RUN --mount=type=secret,id=ca_bundle,target=/tmp/host-ca-bundle.crt,"
        "required=true,mode=0444"
    )
    assert secret_mount in dockerfile
    assert "ca-certificates=20260816ubuntu0.24.04.2" in dockerfile
    assert "git python3 nodejs npm util-linux" in dockerfile
    assert "openssl=3.0.13-0ubuntu3.16" in dockerfile
    assert "libssl3t64=3.0.13-0ubuntu3.16" in dockerfile
    assert "Acquire::https::CaInfo=/tmp/host-ca-bundle.crt" in dockerfile
    assert dockerfile.count("Acquire::https::CaInfo=/tmp/host-ca-bundle.crt") == 2
    assert dockerfile.count("Acquire::Retries=5") == 4
    assert dockerfile.count("Acquire::https::Timeout=30") == 4
    assert dockerfile.count("APT::Update::Error-Mode=any") == 2
    assert "Invalid Ubuntu snapshot identifier" in dockerfile
    assert "Acquire::https::Verify-Peer=false" not in dockerfile
    assert "http://archive.ubuntu.com/ubuntu" not in dockerfile
    assert "RUN --network=none" in dockerfile
    assert "find / -xdev ! -type l -perm /6000" in dockerfile


def test_w2_cross_runtime_jobs_consume_one_normalized_rootfs_artifact() -> None:
    workflow_root = Path(__file__).resolve().parents[2] / ".github" / "workflows"
    firecracker = (workflow_root / "persistent-computer-firecracker-w2.yml").read_text(
        encoding="utf-8"
    )
    base_digest = "ubuntu@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852"
    assert firecracker.count("Build digest-pinned W2 developer image and export rootfs") == 1
    assert base_digest in firecracker
    assert "--build-arg APT_SNAPSHOT=20261106T000000Z" in firecracker
    assert "artifacts/w2-rootfs.tar" in firecracker
    assert firecracker.count("docker build --platform=linux/amd64 --pull --no-cache") == 2
    assert "docker pull --platform linux/amd64" in firecracker
    assert '"platform": "$image_platform"' in firecracker
    assert '"docker_engine_version": "$docker_engine_version"' in firecracker
    assert '"buildx_version": "$buildx_version"' in firecracker
    assert "artifacts/w2-rootfs.rebuild.tar" in firecracker
    assert "cmp --silent artifacts/w2-rootfs.tar artifacts/w2-rootfs.rebuild.tar" in firecracker
    assert "w2-rootfs-reproducibility.json" in firecracker
    assert "rebuild_rootfs_sha256" in firecracker
    assert "byte_identical" in firecracker
    assert "firecracker-w2-${{ github.run_id }}" in firecracker
    assert "path: artifacts/" in firecracker
    assert firecracker.count("--secret id=ca_bundle,src=/tmp/tinlance-ca-bundle.crt") == 2
    assert "ca_bundle_sha256" in firecracker
    assert (
        "install -m 0600 /etc/ssl/certs/ca-certificates.crt /tmp/tinlance-ca-bundle.crt"
        in firecracker
    )
    assert "test ! -L /tmp/tinlance-ca-bundle.crt" in firecracker
    assert "curl --fail --silent --show-error --location" in firecracker
    assert "trap 'rm -f \"$W2_ROOTFS_TAR\"' EXIT" not in firecracker
    assert firecracker.count("needs: guest-boot") == 3
    assert (
        firecracker.count("actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093") == 3
    )
    assert "gvisor-w2:" in firecracker
    assert "kata-w2:" in firecracker
    assert "firecracker-jailer-w2:" in firecracker
    assert "firecracker-jailer-w2.json" in firecracker
    assert "--profile W2" in firecracker
    assert "--network-namespace-path" in firecracker
    assert "ip netns add" in firecracker
    assert "network_namespace_isolated" in firecracker
    assert "host_network_namespace" in firecracker
    assert "process_network_namespace" in firecracker
    assert "npm_install_passed" in firecracker
    assert "package_manifest_reported" in firecracker
    assert "npm_lock_sha256_reported" in firecracker
    assert "git_version_reported" in firecracker
    assert "python_version_reported" in firecracker
    assert "node_version_reported" in firecracker
    assert "npm_version_reported" in firecracker
    assert "--runs 3" in firecracker
    assert "docker import" in firecracker
    assert firecracker.count("--runs 30") >= 3
    kata_workflow = (workflow_root / "persistent-computer-kata-benchmark.yml").read_text(
        encoding="utf-8"
    )
    assert "--retry 12 --retry-all-errors --retry-delay 10" in kata_workflow
    for name in (
        "persistent-computer-gvisor-benchmark.yml",
        "persistent-computer-kata-benchmark.yml",
    ):
        workflow = (workflow_root / name).read_text(encoding="utf-8")
        assert "Build pinned W2 developer-workspace image" not in workflow
        assert "--profile W2" not in workflow
        assert "Run 30" in workflow


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


def test_w2_fixture_git_commit_metadata_is_reproducible() -> None:
    fixture_root = Path(__file__).resolve().parents[1] / "fixtures" / "w2-developer-workspace"
    dockerfile = (fixture_root / "Dockerfile").read_text(encoding="utf-8")
    assert "git -C /opt/tinlance-fixture init --quiet --initial-branch=main" in dockerfile
    assert 'GIT_AUTHOR_DATE="2025-01-01T00:00:00Z"' in dockerfile
    assert 'GIT_COMMITTER_DATE="2025-01-01T00:00:00Z"' in dockerfile
    assert "rm -rf /opt/tinlance-fixture/.git/index /opt/tinlance-fixture/.git/logs" in dockerfile


def test_firecracker_w2_workspace_collects_thirty_samples_for_percentiles() -> None:
    workflow = (
        Path(__file__).resolve().parents[2]
        / ".github"
        / "workflows"
        / "persistent-computer-firecracker-w2.yml"
    ).read_text(encoding="utf-8")
    assert "timeout-minutes: 60" in workflow
    assert "--runs 30 --profile W2" in workflow
    assert 'report.get("sample_count") != 30' in workflow
    assert "len(markers) != 30" in workflow


def test_release_download_workflows_use_pinned_api_fallbacks_and_bounded_retries() -> None:
    workflow_root = Path(__file__).resolve().parents[2] / ".github" / "workflows"
    firecracker = (workflow_root / "persistent-computer-firecracker-w2.yml").read_text(
        encoding="utf-8"
    )
    kata = (workflow_root / "persistent-computer-kata-benchmark.yml").read_text(encoding="utf-8")
    for workflow in (firecracker, kata):
        assert "api.github.com/repos/" in workflow
        assert "--retry 12 --retry-all-errors --retry-delay 10" in workflow
        assert "--connect-timeout 30 --max-time" in workflow
        assert 'test "$downloaded" -eq 1' in workflow
    assert "releases/assets/555159508" in firecracker
    assert "releases/assets/663864062" in kata
    assert "no guest acceptance is claimed" in firecracker
    assert "no benchmark acceptance is claimed" in kata
