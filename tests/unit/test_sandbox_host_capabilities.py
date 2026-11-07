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
    (root / "sys/devices/system/cpu/vulnerabilities").mkdir(parents=True)
    (root / "sys/devices/system/cpu/smt").mkdir(parents=True)
    (root / "sys/class/dmi/id").mkdir(parents=True)
    (root / "dev").mkdir(parents=True)
    (root / "proc/cpuinfo").write_text(
        "processor: 0\nvendor_id: GenuineIntel\nmodel name: Intel Xeon Test\n"
        "cpu family: 6\nmodel: 158\nstepping: 10\nmicrocode: 0x12345678\n"
        "flags: fpu vmx sse4_2\n",
        encoding="utf-8",
    )
    (root / "sys/devices/system/cpu/vulnerabilities/spec_rstack_overflow").write_text(
        "Not affected\n", encoding="utf-8"
    )
    (root / "sys/devices/system/cpu/vulnerabilities/tsa").write_text(
        "Not affected\n", encoding="utf-8"
    )
    (root / "sys/devices/system/cpu/smt/active").write_text("0\n", encoding="utf-8")
    (root / "sys/class/dmi/id/sys_vendor").write_text("Test Vendor\n", encoding="utf-8")
    (root / "sys/class/dmi/id/product_name").write_text("Test Platform\n", encoding="utf-8")
    (root / "sys/class/dmi/id/bios_version").write_text("1.2.3\n", encoding="utf-8")
    (root / "proc/sys/user/max_user_namespaces").write_text("65536\n", encoding="utf-8")
    (root / "proc/self/status").write_text("Name:\tpython\nSeccomp:\t2\n", encoding="utf-8")
    (root / "proc/sys/kernel/seccomp/actions_avail").write_text(
        "kill_process kill_thread trap errno user_notif trace log allow\n", encoding="utf-8"
    )
    (root / "sys/fs/cgroup/cgroup.controllers").write_text("cpu memory pids io\n", encoding="utf-8")
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
    (tmp_path / "proc/sys/kernel/seccomp/actions_avail").unlink()
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
    assert payload["cgroup_controllers"] == ["cpu", "io", "memory", "pids"]
    assert payload["cgroup_limits_ready"] is True
    assert payload["microvm_ready"] is True
    assert json.loads(json.dumps(payload))["kernel_release"] == "test-kernel"


def test_microvm_readiness_requires_cpu_virtualization_extensions(tmp_path: Path) -> None:
    write_probe_fixture(tmp_path, kvm=True)
    (tmp_path / "proc/cpuinfo").write_text("processor: 0\\nflags: fpu sse4_2\\n", encoding="utf-8")
    result = probe_host_capabilities(
        root=tmp_path,
        architecture="x86_64",
        kernel_release="test-kernel",
        binary_lookup=lambda _: None,
        access_check=lambda *_: True,
    )

    assert result.cpu_virtualization is False
    assert result.microvm_ready is False
    assert "CPU virtualization extensions are unavailable" in result.microvm_blockers


def test_microvm_readiness_requires_cpu_memory_and_process_cgroup_controllers(
    tmp_path: Path,
) -> None:
    write_probe_fixture(tmp_path, kvm=True)
    (tmp_path / "sys/fs/cgroup/cgroup.controllers").write_text("memory io\\n", encoding="utf-8")
    result = probe_host_capabilities(
        root=tmp_path,
        architecture="x86_64",
        kernel_release="test-kernel",
        binary_lookup=lambda _: None,
        access_check=lambda *_: True,
    )

    assert result.microvm_ready is False
    assert "required cgroup v2 controllers are unavailable: cpu, pids" in result.microvm_blockers


def test_cpu_security_attestation_surfaces_unmitigated_vulnerability(
    tmp_path: Path,
) -> None:
    write_probe_fixture(tmp_path, kvm=True)
    vulnerability = tmp_path / "sys/devices/system/cpu/vulnerabilities/spec_rstack_overflow"
    vulnerability.write_text("Vulnerable: Safe RET, no microcode\n", encoding="utf-8")

    result = probe_host_capabilities(
        root=tmp_path,
        architecture="x86_64",
        kernel_release="test-kernel",
        binary_lookup=lambda _: None,
        access_check=lambda *_: True,
    )

    payload = result.to_dict()
    assert result.microvm_ready is True
    assert result.cpu_security_mitigations_ready is False
    assert (
        "spec_rstack_overflow: Vulnerable: Safe RET, no microcode"
        in payload["cpu_security_warnings"]
    )
    assert payload["microcode_revision"] == "0x12345678"
    assert payload["cpu_smt_active"] is False
    assert payload["platform_firmware_version"] == "1.2.3"



def test_cpu_security_attestation_rejects_sentinel_microcode_revision(
    tmp_path: Path,
) -> None:
    write_probe_fixture(tmp_path, kvm=True)
    cpuinfo = tmp_path / "proc/cpuinfo"
    cpuinfo.write_text(
        cpuinfo.read_text(encoding="utf-8").replace("0x12345678", "0xffffffff"),
        encoding="utf-8",
    )

    result = probe_host_capabilities(
        root=tmp_path,
        architecture="x86_64",
        kernel_release="test-kernel",
        binary_lookup=lambda _: None,
        access_check=lambda *_: True,
    )

    assert result.cpu_security_mitigations_ready is False
    assert "CPU microcode revision is unavailable, zero or sentinel" in result.cpu_security_warnings
