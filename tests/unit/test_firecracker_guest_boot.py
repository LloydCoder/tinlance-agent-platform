from __future__ import annotations

import pytest
from scripts.smoke_firecracker_guest_boot import (
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
