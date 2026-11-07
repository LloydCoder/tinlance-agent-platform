from __future__ import annotations

import os
import platform
import shutil
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

BinaryLookup = Callable[[str], str | None]
AccessCheck = Callable[[str | os.PathLike[str], int], bool]


@dataclass(frozen=True, slots=True)
class HostCapabilities:
    kernel_release: str
    architecture: str
    cpu_virtualization: bool
    kvm_device_present: bool
    kvm_accessible: bool
    user_namespaces: bool
    cgroup_v2: bool
    cgroup_controllers: tuple[str, ...]
    cgroup_limits_ready: bool
    seccomp_filter_supported: bool
    seccomp_active: bool
    apparmor: bool
    microvm_ready: bool
    microvm_blockers: tuple[str, ...]
    container_sandbox_ready: bool
    container_sandbox_blockers: tuple[str, ...]
    binaries: dict[str, str | None]
    cpu_vendor: str
    cpu_model_name: str
    cpu_family: str
    cpu_model: str
    cpu_stepping: str
    microcode_revision: str
    cpu_smt_active: bool | None
    platform_vendor: str
    platform_product_name: str
    platform_firmware_version: str
    cpu_vulnerabilities: dict[str, str]
    cpu_security_mitigations_ready: bool
    cpu_security_warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["cgroup_controllers"] = list(self.cgroup_controllers)
        payload["microvm_blockers"] = list(self.microvm_blockers)
        payload["container_sandbox_blockers"] = list(self.container_sandbox_blockers)
        payload["cpu_security_warnings"] = list(self.cpu_security_warnings)
        return payload


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _cpuinfo_value(cpuinfo: str, field: str) -> str:
    for line in cpuinfo.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() == field.lower():
            return value.strip()
    return ""


def _cpu_vulnerability_statuses(sysfs: Path) -> dict[str, str]:
    directory = sysfs / "devices/system/cpu/vulnerabilities"
    try:
        paths = sorted(directory.iterdir())
    except OSError:
        return {}
    return {
        path.name: status
        for path in paths
        if path.is_file() and (status := _read_text(path).strip())
    }


def probe_host_capabilities(
    *,
    root: Path = Path("/"),
    architecture: str | None = None,
    kernel_release: str | None = None,
    binary_lookup: BinaryLookup = shutil.which,
    access_check: AccessCheck = os.access,
) -> HostCapabilities:
    """Inspect host prerequisites without modifying the host or installing runtimes."""

    proc = root / "proc"
    sysfs = root / "sys"
    kvm_device = root / "dev/kvm"

    cpuinfo_text = _read_text(proc / "cpuinfo")
    cpuinfo = cpuinfo_text.lower()
    cpu_virtualization = any(flag in cpuinfo.split() for flag in ("vmx", "svm", "virt"))
    cpu_vendor = _cpuinfo_value(cpuinfo_text, "vendor_id") or _cpuinfo_value(
        cpuinfo_text, "CPU implementer"
    )
    cpu_model_name = (
        _cpuinfo_value(cpuinfo_text, "model name")
        or _cpuinfo_value(cpuinfo_text, "Hardware")
        or _cpuinfo_value(cpuinfo_text, "Processor")
    )
    cpu_family = _cpuinfo_value(cpuinfo_text, "cpu family") or _cpuinfo_value(
        cpuinfo_text, "CPU architecture"
    )
    cpu_model = _cpuinfo_value(cpuinfo_text, "model") or _cpuinfo_value(cpuinfo_text, "CPU part")
    cpu_stepping = _cpuinfo_value(cpuinfo_text, "stepping") or _cpuinfo_value(
        cpuinfo_text, "CPU revision"
    )
    microcode_revision = _cpuinfo_value(cpuinfo_text, "microcode")
    smt_status = _read_text(sysfs / "devices/system/cpu/smt/active").strip()
    cpu_smt_active = True if smt_status == "1" else False if smt_status == "0" else None
    platform_vendor = _read_text(sysfs / "class/dmi/id/sys_vendor").strip()
    platform_product_name = _read_text(sysfs / "class/dmi/id/product_name").strip()
    platform_firmware_version = _read_text(sysfs / "class/dmi/id/bios_version").strip()
    cpu_vulnerabilities = _cpu_vulnerability_statuses(sysfs)
    cpu_security_warnings: list[str] = []
    if not cpu_vendor:
        cpu_security_warnings.append("CPU vendor is unavailable")
    if not cpu_model_name:
        cpu_security_warnings.append("CPU model is unavailable")
    if not cpu_family or not cpu_model or not cpu_stepping:
        cpu_security_warnings.append("CPU family/model/stepping identity is incomplete")
    if cpu_smt_active is None:
        cpu_security_warnings.append("CPU SMT state is unavailable")
    if not platform_vendor or not platform_product_name or not platform_firmware_version:
        cpu_security_warnings.append("Platform firmware identity is incomplete")
    if not microcode_revision or microcode_revision.lower() in {
        "0",
        "0x0",
        "0xffffffff",
        "0xffffffffffffffff",
    }:
        cpu_security_warnings.append("CPU microcode revision is unavailable, zero or sentinel")
    if not cpu_vulnerabilities:
        cpu_security_warnings.append("CPU vulnerability sysfs statuses are unavailable")
    for name, status in cpu_vulnerabilities.items():
        normalized_status = status.lower()
        if normalized_status.startswith("vulnerable"):
            cpu_security_warnings.append(f"{name}: {status}")
        elif not normalized_status.startswith(("mitigation:", "not affected")):
            cpu_security_warnings.append(f"{name}: unrecognized status: {status}")
    cpu_security_mitigations_ready = not cpu_security_warnings

    kvm_device_present = kvm_device.exists()
    kvm_accessible = kvm_device_present and access_check(kvm_device, os.R_OK | os.W_OK)

    try:
        max_user_namespaces = int(_read_text(proc / "sys/user/max_user_namespaces").strip() or "0")
    except ValueError:
        max_user_namespaces = 0
    user_namespaces = max_user_namespaces > 0

    cgroup_controller_file = sysfs / "fs/cgroup/cgroup.controllers"
    cgroup_v2 = cgroup_controller_file.is_file()
    cgroup_controllers = tuple(sorted(set(_read_text(cgroup_controller_file).split())))
    required_cgroup_controllers = {"cpu", "memory", "pids"}
    missing_cgroup_controllers = sorted(required_cgroup_controllers - set(cgroup_controllers))
    cgroup_limits_ready = cgroup_v2 and not missing_cgroup_controllers
    status = _read_text(proc / "self/status")
    seccomp_active = any(
        line.startswith("Seccomp:") and line.split(":", 1)[1].strip() in {"1", "2"}
        for line in status.splitlines()
    )
    seccomp_actions = set(_read_text(proc / "sys/kernel/seccomp/actions_avail").split())
    kernel_config = _read_text(root / "boot" / f"config-{kernel_release or platform.release()}")
    seccomp_filter_supported = {"errno", "allow"}.issubset(
        seccomp_actions
    ) or "CONFIG_SECCOMP_FILTER=y" in kernel_config
    apparmor = _read_text(sysfs / "module/apparmor/parameters/enabled").strip().upper() in {
        "Y",
        "YES",
    }

    machine = architecture or platform.machine()
    supported_architectures = {"x86_64", "aarch64", "amd64", "arm64"}
    microvm_blockers: list[str] = []
    if not cpu_virtualization:
        microvm_blockers.append("CPU virtualization extensions are unavailable")
    if not kvm_device_present:
        microvm_blockers.append("KVM device is unavailable")
    elif not kvm_accessible:
        microvm_blockers.append("KVM device is not readable and writable by the runner")
    if machine.lower() not in supported_architectures:
        microvm_blockers.append(f"unsupported microVM host architecture: {machine}")
    if not cgroup_v2:
        microvm_blockers.append("cgroup v2 is unavailable")
    elif not cgroup_limits_ready:
        microvm_blockers.append(
            "required cgroup v2 controllers are unavailable: "
            + ", ".join(missing_cgroup_controllers)
        )
    if not seccomp_filter_supported:
        microvm_blockers.append("kernel seccomp filter support is unavailable")

    container_blockers: list[str] = []
    if not user_namespaces:
        container_blockers.append("unprivileged user namespaces are unavailable")
    if not cgroup_v2:
        container_blockers.append("cgroup v2 is unavailable")
    elif not cgroup_limits_ready:
        container_blockers.append(
            "required cgroup v2 controllers are unavailable: "
            + ", ".join(missing_cgroup_controllers)
        )
    if not seccomp_filter_supported:
        container_blockers.append("seccomp filtering is unavailable")

    binary_names = (
        "firecracker",
        "jailer",
        "runsc",
        "kata-runtime",
        "docker",
        "containerd",
    )
    binaries = {name: binary_lookup(name) for name in binary_names}

    return HostCapabilities(
        kernel_release=kernel_release or platform.release(),
        architecture=machine,
        cpu_virtualization=cpu_virtualization,
        kvm_device_present=kvm_device_present,
        kvm_accessible=kvm_accessible,
        user_namespaces=user_namespaces,
        cgroup_v2=cgroup_v2,
        cgroup_controllers=cgroup_controllers,
        cgroup_limits_ready=cgroup_limits_ready,
        seccomp_filter_supported=seccomp_filter_supported,
        seccomp_active=seccomp_active,
        apparmor=apparmor,
        microvm_ready=not microvm_blockers,
        microvm_blockers=tuple(microvm_blockers),
        container_sandbox_ready=not container_blockers,
        container_sandbox_blockers=tuple(container_blockers),
        binaries=binaries,
        cpu_vendor=cpu_vendor,
        cpu_model_name=cpu_model_name,
        cpu_family=cpu_family,
        cpu_model=cpu_model,
        cpu_stepping=cpu_stepping,
        microcode_revision=microcode_revision,
        cpu_smt_active=cpu_smt_active,
        platform_vendor=platform_vendor,
        platform_product_name=platform_product_name,
        platform_firmware_version=platform_firmware_version,
        cpu_vulnerabilities=cpu_vulnerabilities,
        cpu_security_mitigations_ready=cpu_security_mitigations_ready,
        cpu_security_warnings=tuple(cpu_security_warnings),
    )
