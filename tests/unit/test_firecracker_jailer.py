from __future__ import annotations

import pytest
from scripts.smoke_firecracker_jailer import (
    build_jailer_command,
    verify_jailer_process_evidence,
)


def test_build_jailer_command_uses_unique_id_unprivileged_identity_and_v2_limits() -> None:
    command = build_jailer_command(
        jailer_binary="/usr/local/libexec/firecracker/jailer",
        firecracker_binary="/usr/local/libexec/firecracker/firecracker",
        jailer_id="fc-smoke-421",
        uid=987,
        gid=987,
        chroot_base_dir="/srv/tinlance-jailer",
    )

    assert command == [
        "sudo",
        "-n",
        "/usr/local/libexec/firecracker/jailer",
        "--id",
        "fc-smoke-421",
        "--exec-file",
        "/usr/local/libexec/firecracker/firecracker",
        "--uid",
        "987",
        "--gid",
        "987",
        "--cgroup-version",
        "2",
        "--cgroup",
        "memory.max=805306368",
        "--cgroup",
        "pids.max=128",
        "--cgroup",
        "cpu.max=100000 100000",
        "--chroot-base-dir",
        "/srv/tinlance-jailer",
        "--new-pid-ns",
        "--",
        "--api-sock",
        "/run/firecracker.socket",
    ]


def test_build_jailer_command_rejects_root_identity() -> None:
    with pytest.raises(ValueError, match="non-root"):
        build_jailer_command(
            jailer_binary="/usr/local/libexec/firecracker/jailer",
            firecracker_binary="/usr/local/libexec/firecracker/firecracker",
            jailer_id="fc-smoke-421",
            uid=0,
            gid=987,
            chroot_base_dir="/srv/tinlance-jailer",
        )


def test_build_jailer_command_rejects_unsafe_identifier() -> None:
    with pytest.raises(ValueError, match="identifier"):
        build_jailer_command(
            jailer_binary="/usr/local/libexec/firecracker/jailer",
            firecracker_binary="/usr/local/libexec/firecracker/firecracker",
            jailer_id="../escape",
            uid=987,
            gid=987,
            chroot_base_dir="/srv/tinlance-jailer",
        )


def test_verify_jailer_evidence_requires_unprivileged_seccomp_pid_and_mount_isolation() -> None:
    status = """Name:\tfirecracker
Uid:\t987\t987\t987\t987
Gid:\t987\t987\t987\t987
NSpid:\t4321\t1
NoNewPrivs:\t1
Seccomp:\t2
CapEff:\t0000000000000000
"""
    result = verify_jailer_process_evidence(
        status_text=status,
        cgroup_text="0::/firecracker/fc-smoke-421",
        expected_uid=987,
        expected_gid=987,
        host_mount_namespace="mnt:[4026531840]",
        process_mount_namespace="mnt:[4026532444]",
        host_pid_namespace="pid:[4026531836]",
        process_pid_namespace="pid:[4026532445]",
        expected_chroot_identity="8:12345",
        process_root_identity="8:12345",
    )

    assert result == {
        "uid": 987,
        "gid": 987,
        "seccomp_mode": 2,
        "no_new_privs": True,
        "capabilities_effective": "0000000000000000",
        "pid_namespace_isolated": True,
        "mount_namespace_isolated": True,
        "chroot_identity": "8:12345",
        "cgroup_path": "/firecracker/fc-smoke-421",
    }


def test_verify_jailer_evidence_rejects_root_process() -> None:
    status = """Uid:\t0\t0\t0\t0
Gid:\t987\t987\t987\t987
NSpid:\t4321\t1
NoNewPrivs:\t1
Seccomp:\t2
CapEff:\t0000000000000000
"""
    with pytest.raises(PermissionError, match="uid"):
        verify_jailer_process_evidence(
            status_text=status,
            cgroup_text="0::/firecracker/fc-smoke-421",
            expected_uid=987,
            expected_gid=987,
            host_mount_namespace="mnt:[4026531840]",
            process_mount_namespace="mnt:[4026532444]",
            host_pid_namespace="pid:[4026531836]",
            process_pid_namespace="pid:[4026532445]",
            expected_chroot_identity="8:12345",
            process_root_identity="8:12345",
        )


def test_verify_jailer_evidence_rejects_missing_seccomp() -> None:
    status = """Uid:\t987\t987\t987\t987
Gid:\t987\t987\t987\t987
NSpid:\t4321\t1
NoNewPrivs:\t1
Seccomp:\t0
CapEff:\t0000000000000000
"""
    with pytest.raises(PermissionError, match="seccomp"):
        verify_jailer_process_evidence(
            status_text=status,
            cgroup_text="0::/firecracker/fc-smoke-421",
            expected_uid=987,
            expected_gid=987,
            host_mount_namespace="mnt:[4026531840]",
            process_mount_namespace="mnt:[4026532444]",
            host_pid_namespace="pid:[4026531836]",
            process_pid_namespace="pid:[4026532445]",
            expected_chroot_identity="8:12345",
            process_root_identity="8:12345",
        )


def test_verify_jailer_evidence_rejects_missing_cgroup_v2_membership() -> None:
    status = """Uid:\t987\t987\t987\t987
Gid:\t987\t987\t987\t987
NSpid:\t4321\t1
NoNewPrivs:\t1
Seccomp:\t2
CapEff:\t0000000000000000
"""
    with pytest.raises(PermissionError, match="cgroup v2"):
        verify_jailer_process_evidence(
            status_text=status,
            cgroup_text="2:cpu:/legacy",
            expected_uid=987,
            expected_gid=987,
            host_mount_namespace="mnt:[4026531840]",
            process_mount_namespace="mnt:[4026532444]",
            host_pid_namespace="pid:[4026531836]",
            process_pid_namespace="pid:[4026532445]",
            expected_chroot_identity="8:12345",
            process_root_identity="8:12345",
        )


def test_verify_jailer_evidence_rejects_process_outside_expected_chroot() -> None:
    status = """Uid:\t987\t987\t987\t987
Gid:\t987\t987\t987\t987
NSpid:\t4321\t1
NoNewPrivs:\t1
Seccomp:\t2
CapEff:\t0000000000000000
"""
    with pytest.raises(PermissionError, match="chroot"):
        verify_jailer_process_evidence(
            status_text=status,
            cgroup_text="0::/firecracker/fc-smoke-421",
            expected_uid=987,
            expected_gid=987,
            host_mount_namespace="mnt:[4026531840]",
            process_mount_namespace="mnt:[4026532444]",
            host_pid_namespace="pid:[4026531836]",
            process_pid_namespace="pid:[4026532445]",
            expected_chroot_identity="8:12345",
            process_root_identity="8:12346",
        )
