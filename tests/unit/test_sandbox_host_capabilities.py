from __future__ import annotations

import json
from pathlib import Path

from tinlance_agent_platform_sandbox.host_capabilities import probe_host_capabilities


def write_probe_fixture(root: Path, *, kvm: bool = False) -> None:
    (root / "proc/sys/user").mkdir(parents=True)
    (root / "proc/self").mkdir(parents=True)
    (root / "proc/sys/kernel/seccomp").mkdir(parents=True)
    (root / "sys/fs/cgroup").mkdir(parents=True)
    (root / "sys/module/apparmor/parameters").mkdir(parents=True)
    (root / "dev").mkdir(parents=True)
    (root / "proc/cpuinfo").write_text(
        "processor: 0\nflags: fpu vmx sse4_2\n", encoding="utf-8"
    )
    (root / "proc/sys/user/max_user_namespaces").write_text("65536\n", encoding="utf-8")
    (root / "proc/self/status").write_text("Name:\tpython\nSeccomp:\t2\n", encoding="utf-8")
    (root / "sys/fs/cgroup/cgroup.controllers").write_text(
        "cpu memory pids io\n", encoding="utf-8"
    )
    (root / "sys/module/apparmor/parameters/enabled").write_text("Y\n", encoding="utf-8")
    if kvm:
        (root / "dev/kvm").touch()


def test_microvm_readiness_requires_accessible_kvm_device(tmp_path: Path) -> None:
    write_probe_fixture(tmp_path)
    result = probe_host_capabilities(
        root=tmp_path,
        architecture="x86_64",
        kernel_release="test-kernel",
        binary_lookup=lambda _: None,
        access_check=lambda *_: True,
    )

    assert result.microvm_ready is False
    assert result.microvm_blockers == ("KVM device is unavailable",)
    assert result.container_sandbox_ready is True
    assert result.seccomp_filter_supported is True
    assert result.seccomp_active is True


def test_microvm_readiness_requires_device_permissions(tmp_path: Path) -> None:
    write_probe_fixture(tmp_path, kvm=True)
    result = probe_host_capabilities(
        root=tmp_path,
        architecture="x86_64",
        kernel_release="test-kernel",
        binary_lookup=lambda _: None,
        access_check=lambda *_: False,
    )

    assert result.kvm_device_present is True
    assert result.kvm_accessible is False
    assert "KVM device is not readable and writable by the runner" in result.microvm_blockers


def test_microvm_readiness_accepts_supported_kvm_host(tmp_path: Path) -> None:
    write_probe_fixture(tmp_path, kvm=True)
    result = probe_host_capabilities(
        root=tmp_path,
        architecture="x86_64",
        kernel_release="test-kernel",
        binary_lookup=lambda _: None,
        access_check=lambda *_: True,
    )

    assert result.microvm_ready is True
    assert result.microvm_blockers == ()
    assert result.cpu_virtualization is True


def test_container_sandbox_requires_userns_cgroup_v2_and_seccomp(tmp_path: Path) -> None:
    write_probe_fixture(tmp_path)
    (tmp_path / "proc/sys/user/max_user_namespaces").write_text("0\n", encoding="utf-8")
    (tmp_path / "proc/self/status").write_text("Name:\tpython\nSeccomp:\t0\n", encoding="utf-8")
    (tmp_path / "sys/fs/cgroup/cgroup.controllers").unlink()

    result = probe_host_capabilities(
        root=tmp_path,
        architecture="x86_64",
        kernel_release="test-kernel",
        binary_lookup=lambda _: None,
        access_check=lambda *_: False,
    )

    assert result.container_sandbox_ready is False
    assert result.seccomp_filter_supported is False
    assert result.seccomp_active is False
    assert set(result.container_sandbox_blockers) == {
        "unprivileged user namespaces are unavailable",
        "cgroup v2 is unavailable",
        "seccomp filtering is unavailable",
    }


def test_probe_reports_tooling_and_serializable_evidence(tmp_path: Path) -> None:
    write_probe_fixture(tmp_path, kvm=True)
    binaries = {
        "firecracker": "/usr/bin/firecracker",
        "jailer": "/usr/bin/jailer",
        "runsc": "/usr/bin/runsc",
        "kata-runtime": "/usr/bin/kata-runtime",
        "docker": "/usr/bin/docker",
        "containerd": "/usr/bin/containerd",
    }
    result = probe_host_capabilities(
        root=tmp_path,
        architecture="aarch64",
        kernel_release="test-kernel",
        binary_lookup=binaries.get,
        access_check=lambda *_: True,
    )

    payload = result.to_dict()
    assert payload["binaries"] == binaries
    assert payload["architecture"] == "aarch64"
    assert payload["microvm_ready"] is True
    assert json.loads(json.dumps(payload))["kernel_release"] == "test-kernel"
