from __future__ import annotations

import json
import tarfile
from pathlib import Path

import pytest
from scripts.smoke_firecracker_guest_boot import (
    extract_w2_rootfs_tar,
    load_asset_manifest,
    parse_latest_artifact_prefix,
    select_latest_versioned_key,
    summarize_boot_times,
)


def test_parse_latest_firecracker_ci_prefix_uses_newest_build() -> None:
    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
      <CommonPrefixes><Prefix>firecracker-ci/20261104-build-a/</Prefix></CommonPrefixes>
      <CommonPrefixes><Prefix>firecracker-ci/20261106-build-b/</Prefix></CommonPrefixes>
      <CommonPrefixes><Prefix>firecracker-ci/20261105-build-c/</Prefix></CommonPrefixes>
    </ListBucketResult>"""

    assert parse_latest_artifact_prefix(xml) == "firecracker-ci/20261106-build-b/"


def test_select_latest_kernel_key_uses_numeric_version_order() -> None:
    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
      <Contents><Key>firecracker-ci/20261106-build/x86_64/vmlinux-6.9.12</Key></Contents>
      <Contents><Key>firecracker-ci/20261106-build/x86_64/vmlinux-6.10.2</Key></Contents>
      <Contents><Key>firecracker-ci/20261106-build/x86_64/vmlinux-6.10.11</Key></Contents>
    </ListBucketResult>"""

    assert (
        select_latest_versioned_key(
            xml,
            "firecracker-ci/20261106-build/x86_64/",
            r"vmlinux-(\d+)\.(\d+)\.(\d+)$",
        )
        == "firecracker-ci/20261106-build/x86_64/vmlinux-6.10.11"
    )


def test_select_latest_ubuntu_rootfs_key_uses_numeric_version_order() -> None:
    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
      <Contents><Key>firecracker-ci/20261106-build/x86_64/ubuntu-22.04.squashfs</Key></Contents>
      <Contents><Key>firecracker-ci/20261106-build/x86_64/ubuntu-24.04.squashfs</Key></Contents>
    </ListBucketResult>"""

    assert (
        select_latest_versioned_key(
            xml,
            "firecracker-ci/20261106-build/x86_64/",
            r"ubuntu-(\d+)\.(\d+)\.squashfs$",
        )
        == "firecracker-ci/20261106-build/x86_64/ubuntu-24.04.squashfs"
    )


def test_summarize_boot_times_reports_median_and_max_for_small_samples() -> None:
    assert summarize_boot_times([120.0, 100.0, 140.0]) == {
        "sample_count": 3,
        "median_boot_time_ms": 120.0,
        "max_boot_time_ms": 140.0,
    }


def test_summarize_boot_times_rejects_empty_samples() -> None:
    with pytest.raises(ValueError, match="at least one"):
        summarize_boot_times([])


def test_load_pinned_guest_asset_manifest_matches_runner_architecture() -> None:
    manifest_path = (
        Path(__file__).resolve().parents[1] / "fixtures" / "firecracker-guest-assets.json"
    )
    manifest = load_asset_manifest(manifest_path, "x86_64")

    assert manifest["kernel_key"].endswith("vmlinux-6.18.56")
    assert manifest["rootfs_key"].endswith("ubuntu-24.04.squashfs")
    assert len(manifest["kernel_sha256"]) == 64
    assert len(manifest["rootfs_squashfs_sha256"]) == 64


def test_load_guest_asset_manifest_rejects_architecture_mismatch() -> None:
    manifest_path = (
        Path(__file__).resolve().parents[1] / "fixtures" / "firecracker-guest-assets.json"
    )

    with pytest.raises(ValueError, match="architecture"):
        load_asset_manifest(manifest_path, "aarch64")


def test_load_guest_asset_manifest_rejects_key_outside_pinned_prefix(tmp_path: Path) -> None:
    manifest_path = (
        Path(__file__).resolve().parents[1] / "fixtures" / "firecracker-guest-assets.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["kernel_key"] = manifest["artifact_prefix"] + "x86_64/../vmlinux-6.18.56"
    tampered_path = tmp_path / "tampered-assets.json"
    tampered_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="outside its artifact prefix"):
        load_asset_manifest(tampered_path, "x86_64")


def test_load_guest_asset_manifest_rejects_invalid_digest(tmp_path: Path) -> None:
    manifest_path = (
        Path(__file__).resolve().parents[1] / "fixtures" / "firecracker-guest-assets.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["kernel_sha256"] = "not-a-sha256"
    tampered_path = tmp_path / "tampered-assets.json"
    tampered_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="kernel_sha256"):
        load_asset_manifest(tampered_path, "x86_64")


def test_guest_init_rejects_writable_rootfs_before_ready_marker() -> None:
    from scripts.smoke_firecracker_guest_boot import guest_init_script

    script = guest_init_script()
    assert "touch /etc/tinlance-write-probe" in script
    assert "TINLANCE_ROOTFS_WRITE_UNEXPECTED" in script
    assert "TINLANCE_ROOTFS_READ_ONLY_CONFIRMED" in script
    assert script.index("TINLANCE_ROOTFS_READ_ONLY_CONFIRMED") < script.index(
        "TINLANCE_GUEST_READY"
    )


def test_guest_init_rejects_non_loopback_network_interfaces() -> None:
    from scripts.smoke_firecracker_guest_boot import guest_init_script

    script = guest_init_script()
    assert "mount -t sysfs sysfs /sys" in script
    assert 'if [ "$iface" != "lo" ]' in script
    assert "TINLANCE_NETWORK_INTERFACE_UNEXPECTED" in script
    assert "TINLANCE_NO_NIC_CONFIRMED" in script
    assert script.index("TINLANCE_NO_NIC_CONFIRMED") < script.index("TINLANCE_GUEST_READY")


def test_guest_init_executes_nonroot_w1_workload_in_owned_tmpfs_before_ready() -> None:
    from scripts.smoke_firecracker_guest_boot import guest_init_script

    script = guest_init_script()
    assert "setpriv --reuid=65532 --regid=65532 --clear-groups" in script
    assert 'test "$(id -u)" = 65532' in script
    assert "TINLANCE_NONROOT_UID_CONFIRMED" in script
    assert "mode=0700,uid=65532,gid=65532" in script
    assert "printf tinlance-gvisor-ok > /tmp/workload.txt" in script
    assert 'test "$(cat /tmp/workload.txt)" = tinlance-gvisor-ok' in script
    assert script.index("TINLANCE_NO_NIC_CONFIRMED") < script.index(
        "TINLANCE_NONROOT_UID_CONFIRMED"
    )
    assert script.index("TINLANCE_NONROOT_UID_CONFIRMED") < script.index("TINLANCE_W1_WORKLOAD_OK")
    assert script.index("TINLANCE_W1_WORKLOAD_OK") < script.index("TINLANCE_GUEST_READY")


def test_ensure_w1_user_adds_deterministic_passwd_group_and_home(tmp_path: Path) -> None:
    from scripts.smoke_firecracker_guest_boot import ensure_w1_user

    rootfs = tmp_path / "rootfs"
    (rootfs / "etc").mkdir(parents=True)
    (rootfs / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/sh\n",
        encoding="utf-8",
    )
    (rootfs / "etc" / "group").write_text("root:x:0:\n", encoding="utf-8")

    ensure_w1_user(rootfs)
    ensure_w1_user(rootfs)

    passwd = (rootfs / "etc" / "passwd").read_text(encoding="utf-8")
    group = (rootfs / "etc" / "group").read_text(encoding="utf-8")
    assert passwd.count("tinlance:x:65532:65532:") == 1
    assert group.count("tinlance:x:65532:") == 1
    assert (rootfs / "home" / "tinlance").is_dir()
    assert (rootfs / "home" / "tinlance").stat().st_mode & 0o777 == 0o700


def test_ensure_w1_user_rejects_uid_collision(tmp_path: Path) -> None:
    from scripts.smoke_firecracker_guest_boot import ensure_w1_user

    rootfs = tmp_path / "rootfs"
    (rootfs / "etc").mkdir(parents=True)
    (rootfs / "etc" / "passwd").write_text(
        "other:x:65532:65532:Other:/home/other:/bin/sh\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="UID 65532"):
        ensure_w1_user(rootfs)


def test_summarize_boot_times_reports_p95_and_p99_with_thirty_samples() -> None:
    samples = [float(value) for value in range(1, 31)]
    report = summarize_boot_times(samples)
    assert report["sample_count"] == 30
    assert report["p95_boot_time_ms"] == 29.0
    assert report["p99_boot_time_ms"] == 30.0


def test_guest_boot_marker_verifier_accepts_isolated_nonroot_w1_evidence() -> None:
    from scripts.smoke_firecracker_guest_boot import verify_guest_boot_markers

    evidence = verify_guest_boot_markers(
        "TINLANCE_NO_NIC_CONFIRMED\nTINLANCE_ROOTFS_READ_ONLY_CONFIRMED\n"
        "TINLANCE_NONROOT_UID_CONFIRMED\nTINLANCE_W1_WORKLOAD_OK\nTINLANCE_GUEST_READY"
    )
    assert evidence == {
        "rootfs_read_only_confirmed": True,
        "no_non_loopback_network_interfaces": True,
        "nonroot_uid_confirmed": True,
        "w1_workload_passed": True,
        "guest_ready": True,
    }


def test_guest_boot_marker_verifier_rejects_writable_rootfs() -> None:
    from scripts.smoke_firecracker_guest_boot import verify_guest_boot_markers

    with pytest.raises(PermissionError, match="accepted a write"):
        verify_guest_boot_markers("TINLANCE_ROOTFS_WRITE_UNEXPECTED\nTINLANCE_GUEST_READY")


def test_guest_boot_marker_verifier_rejects_non_loopback_network_interface() -> None:
    from scripts.smoke_firecracker_guest_boot import verify_guest_boot_markers

    with pytest.raises(PermissionError, match="non-loopback"):
        verify_guest_boot_markers("TINLANCE_NETWORK_INTERFACE_UNEXPECTED\nTINLANCE_GUEST_READY")


def test_guest_boot_marker_verifier_rejects_missing_isolation_evidence() -> None:
    from scripts.smoke_firecracker_guest_boot import verify_guest_boot_markers

    with pytest.raises(ValueError, match="markers are missing"):
        verify_guest_boot_markers("TINLANCE_GUEST_READY")


def test_guest_boot_marker_verifier_rejects_missing_nonroot_w1_evidence() -> None:
    from scripts.smoke_firecracker_guest_boot import verify_guest_boot_markers

    with pytest.raises(ValueError, match="nonroot_uid_confirmed"):
        verify_guest_boot_markers(
            "TINLANCE_NO_NIC_CONFIRMED\\nTINLANCE_ROOTFS_READ_ONLY_CONFIRMED\\nTINLANCE_GUEST_READY"
        )


def test_guest_init_w2_enforces_no_new_privileges_and_host_surface_denials() -> None:
    from scripts.smoke_firecracker_guest_boot import guest_init_script

    script = guest_init_script("W2")
    assert "setpriv --no-new-privs --reuid=65532 --regid=65532 --clear-groups" in script
    assert script.count("set -eu") >= 2
    for marker in (
        "TINLANCE_W2_CAPABILITIES_DROPPED",
        "TINLANCE_W2_NO_NEW_PRIVS_CONFIRMED",
        "TINLANCE_W2_SENSITIVE_FILES_DENIED",
        "TINLANCE_W2_HOST_DEVICES_ABSENT",
        "TINLANCE_W2_HOST_SOCKETS_ABSENT",
        "TINLANCE_W2_PRIVILEGE_ESCALATION_DENIED",
        "TINLANCE_W2_MOUNT_PRIVILEGE_DENIED",
        "TINLANCE_W2_PROC_SYS_READONLY",
        "TINLANCE_W2_HOST_SURFACE_PROBES_OK",
    ):
        assert marker in script
    assert script.index("TINLANCE_W2_HOST_SURFACE_PROBES_OK") < script.index("TINLANCE_GUEST_READY")


def test_guest_boot_w2_verifier_requires_every_host_surface_marker() -> None:
    from scripts.smoke_firecracker_guest_boot import verify_guest_boot_markers

    markers = [
        "TINLANCE_ROOTFS_READ_ONLY_CONFIRMED",
        "TINLANCE_NO_NIC_CONFIRMED",
        "TINLANCE_NONROOT_UID_CONFIRMED",
        "TINLANCE_W1_WORKLOAD_OK",
        "TINLANCE_W2_CAPABILITIES_DROPPED",
        "TINLANCE_W2_NO_NEW_PRIVS_CONFIRMED",
        "TINLANCE_W2_SENSITIVE_FILES_DENIED",
        "TINLANCE_W2_HOST_DEVICES_ABSENT",
        "TINLANCE_W2_HOST_SOCKETS_ABSENT",
        "TINLANCE_W2_PRIVILEGE_ESCALATION_DENIED",
        "TINLANCE_W2_MOUNT_PRIVILEGE_DENIED",
        "TINLANCE_W2_PROC_SYS_READONLY",
        "TINLANCE_W2_HOST_SURFACE_PROBES_OK",
        "TINLANCE_W2_WORKSPACE_TMPFS_MOUNTED",
        "TINLANCE_W2_DEVELOPER_WORKSPACE_OK",
        "TINLANCE_W2_GIT_VERSION=git version",
        "TINLANCE_W2_PYTHON_VERSION=Python",
        "TINLANCE_W2_NODE_VERSION=v",
        "TINLANCE_W2_NPM_VERSION=",
        "TINLANCE_GUEST_READY",
    ]
    evidence = verify_guest_boot_markers("\\n".join(markers), "W2")
    assert evidence["host_surface_probes_passed"] is True
    assert evidence["no_new_privileges"] is True


def test_guest_boot_w2_verifier_rejects_missing_and_violating_markers() -> None:
    from scripts.smoke_firecracker_guest_boot import verify_guest_boot_markers

    with pytest.raises(ValueError, match="host_surface_probes_passed"):
        verify_guest_boot_markers(
            "TINLANCE_ROOTFS_READ_ONLY_CONFIRMED\\n"
            "TINLANCE_NO_NIC_CONFIRMED\\n"
            "TINLANCE_NONROOT_UID_CONFIRMED\\n"
            "TINLANCE_W1_WORKLOAD_OK\\n"
            "TINLANCE_GUEST_READY",
            "W2",
        )
    with pytest.raises(PermissionError, match="privilege escalation"):
        verify_guest_boot_markers("TINLANCE_W2_PRIVILEGE_ESCALATION_UNEXPECTED", "W2")


def test_guest_init_w2_script_is_valid_posix_shell() -> None:
    import subprocess

    from scripts.smoke_firecracker_guest_boot import guest_init_script

    result = subprocess.run(
        ["sh", "-n"],
        input=guest_init_script("W2"),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_guest_init_w2_runs_real_developer_workspace_in_bounded_tmpfs() -> None:
    from scripts.smoke_firecracker_guest_boot import guest_init_script

    script = guest_init_script("W2")
    assert (
        "mount -t tmpfs -o size=128m,mode=0700,uid=65532,gid=65532,"
        "noexec,nosuid,nodev tmpfs /workspace"
    ) in script
    fixture_script = (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "w2-developer-workspace"
        / "run-workspace.sh"
    ).read_text(encoding="utf-8")
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
        assert marker in fixture_script or marker in script
    assert "/opt/tinlance-fixture/run-workspace.sh" in script
    assert script.index("TINLANCE_W2_DEVELOPER_WORKSPACE_OK") < script.index(
        "TINLANCE_GUEST_READY"
    )


def test_guest_boot_w2_verifier_requires_developer_workspace_markers() -> None:
    from scripts.smoke_firecracker_guest_boot import verify_guest_boot_markers

    markers = [
        "TINLANCE_ROOTFS_READ_ONLY_CONFIRMED",
        "TINLANCE_NO_NIC_CONFIRMED",
        "TINLANCE_NONROOT_UID_CONFIRMED",
        "TINLANCE_W1_WORKLOAD_OK",
        "TINLANCE_W2_CAPABILITIES_DROPPED",
        "TINLANCE_W2_NO_NEW_PRIVS_CONFIRMED",
        "TINLANCE_W2_SENSITIVE_FILES_DENIED",
        "TINLANCE_W2_HOST_DEVICES_ABSENT",
        "TINLANCE_W2_HOST_SOCKETS_ABSENT",
        "TINLANCE_W2_PRIVILEGE_ESCALATION_DENIED",
        "TINLANCE_W2_MOUNT_PRIVILEGE_DENIED",
        "TINLANCE_W2_PROC_SYS_READONLY",
        "TINLANCE_W2_HOST_SURFACE_PROBES_OK",
        "TINLANCE_W2_WORKSPACE_TMPFS_MOUNTED",
        "TINLANCE_W2_GIT_CLONE_OK",
        "TINLANCE_W2_PYTHON_EDIT_OK",
        "TINLANCE_W2_PYTHON_BUILD_OK",
        "TINLANCE_W2_PYTHON_TESTS_OK",
        "TINLANCE_W2_NODE_EDIT_OK",
        "TINLANCE_W2_NODE_BUILD_OK",
        "TINLANCE_W2_NODE_TESTS_OK",
        "TINLANCE_W2_WORKTREE_DIRTY_OK",
        "TINLANCE_W2_DEVELOPER_WORKSPACE_OK",
        "TINLANCE_W2_GIT_VERSION=",
        "TINLANCE_W2_PYTHON_VERSION=",
        "TINLANCE_W2_NODE_VERSION=",
        "TINLANCE_W2_NPM_VERSION=",
        "TINLANCE_GUEST_READY",
    ]
    evidence = verify_guest_boot_markers("\\n".join(markers), "W2")
    assert evidence["developer_workspace_passed"] is True


def test_w2_rootfs_tar_extracts_safe_paths(tmp_path: Path) -> None:
    archive = tmp_path / "rootfs.tar"
    source = tmp_path / "source"
    source.mkdir()
    (source / "tool.txt").write_text("synthetic", encoding="utf-8")
    with tarfile.open(archive, "w") as handle:
        handle.add(source / "tool.txt", arcname="opt/tool.txt")

    destination = tmp_path / "rootfs"
    extract_w2_rootfs_tar(archive, destination)
    assert (destination / "opt/tool.txt").read_text(encoding="utf-8") == "synthetic"


def test_w2_rootfs_tar_rejects_path_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe-rootfs.tar"
    item = tarfile.TarInfo("../escape.txt")
    item.size = len(b"unsafe")
    with tarfile.open(archive, "w") as handle:
        import io

        handle.addfile(item, io.BytesIO(b"unsafe"))

    with pytest.raises(ValueError, match="unsafe rootfs archive"):
        extract_w2_rootfs_tar(archive, tmp_path / "rootfs")


def test_w2_rootfs_preparation_requires_content_addressed_oci_export(tmp_path: Path) -> None:
    from scripts.smoke_firecracker_guest_boot import _prepare_rootfs

    with pytest.raises(ValueError, match="W2 rootfs tar"):
        _prepare_rootfs(
            tmp_path / "unused.squashfs",
            tmp_path / "rootfs.ext4",
            tmp_path / "extract",
            "W2",
        )


def test_w2_rootfs_tar_normalizes_safe_absolute_guest_symlinks(tmp_path: Path) -> None:
    import io
    import os

    archive = tmp_path / "symlink-rootfs.tar"
    with tarfile.open(archive, "w") as handle:
        target = tarfile.TarInfo("usr/bin/python3")
        target.size = len(b"python")
        handle.addfile(target, io.BytesIO(b"python"))
        link = tarfile.TarInfo("etc/python3")
        link.type = tarfile.SYMTYPE
        link.linkname = "/usr/bin/python3"
        handle.addfile(link)

    destination = tmp_path / "rootfs"
    extract_w2_rootfs_tar(archive, destination)
    assert os.readlink(destination / "etc/python3") == "../usr/bin/python3"


def test_w2_cli_fails_closed_without_content_addressed_oci_rootfs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import sys

    from scripts.smoke_firecracker_guest_boot import main

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "smoke_firecracker_guest_boot.py",
            "--profile",
            "W2",
            "--output",
            str(tmp_path / "report.json"),
        ],
    )
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
