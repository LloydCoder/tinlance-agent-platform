from __future__ import annotations

import os
import platform
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable


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
    seccomp: bool
    apparmor: bool
    microvm_ready: bool
    microvm_blockers: tuple[str, ...]
    container_sandbox_ready: bool
    container_sandbox_blockers: tuple[str, ...]
    binaries: dict[str, str | None]

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["microvm_blockers"] = list(self.microvm_blockers)
        payload["container_sandbox_blockers"] = list(self.container_sandbox_blockers)
        return payload


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


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

    cpuinfo = _read_text(proc / "cpuinfo").lower()
    cpu_virtualization = any(
        flag in cpuinfo.split()
        for flag in ("vmx", "svm", "virt")
    )

    kvm_device_present = kvm_device.exists()
    kvm_accessible = kvm_device_present and access_check(
        kvm_device, os.R_OK | os.W_OK
    )

    try:
        max_user_namespaces = int(
            _read_text(proc / "sys/user/max_user_namespaces").strip() or "0"
        )
    except ValueError:
        max_user_namespaces = 0
    user_namespaces = max_user_namespaces > 0

    cgroup_v2 = (sysfs / "fs/cgroup/cgroup.controllers").is_file()
    status = _read_text(proc / "self/status")
    seccomp = any(
        line.strip() == "Seccomp:\t2"
        for line in status.splitlines()
    )
    apparmor = _read_text(
        sysfs / "module/apparmor/parameters/enabled"
    ).strip().upper() in {"Y", "YES"}

    machine = architecture or platform.machine()
    supported_architectures = {"x86_64", "aarch64", "amd64", "arm64"}
    microvm_blockers: list[str] = []
    if not kvm_device_present:
        microvm_blockers.append("KVM device is unavailable")
    elif not kvm_accessible:
        microvm_blockers.append(
            "KVM device is not readable and writable by the runner"
        )
    if machine.lower() not in supported_architectures:
        microvm_blockers.append(
            f"unsupported microVM host architecture: {machine}"
        )

    container_blockers: list[str] = []
    if not user_namespaces:
        container_blockers.append("unprivileged user namespaces are unavailable")
    if not cgroup_v2:
        container_blockers.append("cgroup v2 is unavailable")
    if not seccomp:
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
        seccomp=seccomp,
        apparmor=apparmor,
        microvm_ready=not microvm_blockers,
        microvm_blockers=tuple(microvm_blockers),
        container_sandbox_ready=not container_blockers,
        container_sandbox_blockers=tuple(container_blockers),
        binaries=binaries,
    )
