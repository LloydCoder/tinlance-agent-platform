from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.smoke_firecracker_guest_boot import (
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


def test_summarize_boot_times_reports_median_and_max_without_claiming_p95() -> None:
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
