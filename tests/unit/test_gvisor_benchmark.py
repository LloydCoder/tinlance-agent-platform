from __future__ import annotations

import pytest
from scripts.benchmark_gvisor import (
    build_docker_command,
    percentile_nearest_rank,
    summarize_samples,
)


def test_percentile_nearest_rank_is_deterministic_for_three_samples() -> None:
    assert percentile_nearest_rank([10.0, 20.0, 30.0], 50) == 20.0
    assert percentile_nearest_rank([10.0, 20.0, 30.0], 95) == 30.0
    assert percentile_nearest_rank([10.0, 20.0, 30.0], 99) == 30.0


def test_percentile_rejects_invalid_samples_and_percentile() -> None:
    with pytest.raises(ValueError):
        percentile_nearest_rank([], 95)
    with pytest.raises(ValueError):
        percentile_nearest_rank([1.0], 0)
    with pytest.raises(ValueError):
        percentile_nearest_rank([1.0], 101)


def test_summary_requires_at_least_three_samples() -> None:
    with pytest.raises(ValueError, match="three"):
        summarize_samples([1.0, 2.0])


def test_summary_reports_sample_count_and_tail_latency() -> None:
    report = summarize_samples([30.0, 10.0, 20.0])
    assert report == {
        "sample_count": 3,
        "min_ms": 10.0,
        "median_ms": 20.0,
        "p95_ms": 30.0,
        "p99_ms": 30.0,
        "max_ms": 30.0,
    }


def test_docker_command_enforces_restricted_profile() -> None:
    command = build_docker_command(
        image_digest="ubuntu@sha256:" + "a" * 64,
        payload="printf tinlance-gvisor-ok",
    )
    assert command[:3] == ["docker", "run", "--rm"]
    assert "--runtime=runsc" in command
    assert "--network=none" in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--memory=512m" in command
    assert "--cpus=1" in command
    assert "--pids-limit=128" in command
    assert "ubuntu@sha256:" + "a" * 64 in command


def test_docker_command_rejects_mutable_image_reference() -> None:
    with pytest.raises(ValueError, match="digest"):
        build_docker_command(image_digest="ubuntu:24.04", payload="true")


def test_docker_command_rejects_empty_payload() -> None:
    with pytest.raises(ValueError, match="payload"):
        build_docker_command(
            image_digest="ubuntu@sha256:" + "a" * 64,
            payload="",
        )


def test_docker_command_supports_kata_runtime_without_weakening_profile() -> None:
    command = build_docker_command(
        image_digest="ubuntu@sha256:" + "a" * 64,
        payload="printf tinlance-kata-ok",
        runtime_name="kata",
    )
    assert "--runtime=kata" in command
    assert "--network=none" in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command


def test_docker_command_rejects_unsafe_runtime_name() -> None:
    with pytest.raises(ValueError, match="runtime name"):
        build_docker_command(
            image_digest="ubuntu@sha256:" + "a" * 64,
            payload="true",
            runtime_name="../../runsc",
        )


def test_docker_command_rejects_nul_payload() -> None:
    with pytest.raises(ValueError, match="payload"):
        build_docker_command(
            image_digest="ubuntu@sha256:" + "a" * 64,
            payload="unsafe\x00payload",
        )


def test_docker_command_runs_as_unprivileged_identity_with_owned_tmpfs() -> None:
    command = build_docker_command(
        image_digest="ubuntu@sha256:" + "a" * 64,
        payload="printf tinlance-w1-ok",
    )
    assert "--user=65532:65532" in command
    assert "/tmp:rw,noexec,nosuid,nodev,size=64m,uid=65532,gid=65532,mode=0700" in command


def test_w1_payload_verifies_nonroot_readonly_rootfs_and_isolated_network() -> None:
    from scripts.benchmark_gvisor import build_w1_payload

    payload = build_w1_payload()
    assert 'test "$(id -u)" = 65532' in payload
    assert "TINLANCE_NONROOT_UID_CONFIRMED" in payload
    assert "/proc/mounts" in payload
    assert "TINLANCE_ROOTFS_READ_ONLY_CONFIRMED" in payload
    assert "/proc/net/dev" in payload
    assert "TINLANCE_NO_NIC_CONFIRMED" in payload
    assert "/tmp/workload.txt" in payload

def test_w2_payload_requires_capability_and_host_surface_denials() -> None:
    from scripts.benchmark_gvisor import build_w2_payload

    payload = build_w2_payload()
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
        assert marker in payload
    assert "TINLANCE_W2_PRIVILEGE_ESCALATION_UNEXPECTED" in payload
    assert "TINLANCE_W2_MOUNT_PRIVILEGE_UNEXPECTED" in payload


def test_w2_payload_retains_w1_network_and_filesystem_contract() -> None:
    from scripts.benchmark_gvisor import build_w2_payload

    payload = build_w2_payload()
    assert "TINLANCE_NONROOT_UID_CONFIRMED" in payload
    assert "TINLANCE_ROOTFS_READ_ONLY_CONFIRMED" in payload
    assert "TINLANCE_NO_NIC_CONFIRMED" in payload
    assert "/tmp/workload.txt" in payload


def test_docker_command_w2_profile_keeps_all_outer_security_controls() -> None:
    from scripts.benchmark_gvisor import build_w2_payload

    command = build_docker_command(
        image_digest="ubuntu@sha256:" + "a" * 64,
        payload=build_w2_payload(),
        runtime_name="kata",
    )
    for option in (
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=65532:65532",
        "--pids-limit=128",
    ):
        assert option in command

