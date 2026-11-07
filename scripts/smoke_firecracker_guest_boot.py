from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, TypedDict, cast
from urllib.parse import urlencode

S3_BASE = "https://s3.amazonaws.com/spec.ccfc.min"
FIRECRACKER_VERSION = "1.17.0"
GUEST_READY_MARKER = "TINLANCE_GUEST_READY"
GUEST_READ_ONLY_MARKER = "TINLANCE_ROOTFS_READ_ONLY_CONFIRMED"
GUEST_NO_NIC_MARKER = "TINLANCE_NO_NIC_CONFIRMED"
GUEST_WRITE_UNEXPECTED_MARKER = "TINLANCE_ROOTFS_WRITE_UNEXPECTED"
GUEST_NIC_UNEXPECTED_MARKER = "TINLANCE_NETWORK_INTERFACE_UNEXPECTED"
GUEST_W2_UNEXPECTED_MARKERS = (
    "TINLANCE_W2_PRIVILEGE_ESCALATION_UNEXPECTED",
    "TINLANCE_W2_MOUNT_PRIVILEGE_UNEXPECTED",
    "TINLANCE_W2_DEVELOPER_WORKSPACE_FAILED",
    "TINLANCE_W2_GUEST_MEM_DEVICE_READABLE_UNEXPECTED",
)
FIRECRACKER_ARCHIVE_SHA256 = "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558"


def machine_config_for_profile(profile: str) -> dict[str, int | bool]:
    """Return the bounded Firecracker machine profile; reject unknown profiles."""
    profiles: dict[str, dict[str, int | bool]] = {
        "W1": {"vcpu_count": 1, "mem_size_mib": 512, "smt": False},
        "W2": {"vcpu_count": 2, "mem_size_mib": 2048, "smt": False},
    }
    try:
        return profiles[profile].copy()
    except KeyError as exc:
        raise ValueError("profile must be W1 or W2") from exc


_OCI_IMAGE_DIGEST = re.compile(r"^[A-Za-z0-9./:_-]+@sha256:[a-f0-9]{64}$")
_OCI_IMAGE_ID = re.compile(r"^sha256:[a-f0-9]{64}$")


class GuestAssetManifest(TypedDict):
    schema_version: int
    architecture: str
    source: str
    discovered_at: str
    artifact_prefix: str
    kernel_key: str
    kernel_sha256: str
    rootfs_key: str
    rootfs_squashfs_sha256: str


def _xml_values(xml_text: str, element_suffix: str) -> list[str]:
    root = ET.fromstring(xml_text)
    return [
        element.text
        for element in root.iter()
        if element.tag.endswith(element_suffix) and element.text is not None
    ]


def parse_latest_artifact_prefix(xml_text: str) -> str:
    prefixes = [
        value
        for value in _xml_values(xml_text, "Prefix")
        if re.fullmatch(r"firecracker-ci/\d{8}-[^/]+/", value)
    ]
    if not prefixes:
        raise ValueError("Firecracker CI artifact listing contains no dated build prefixes")
    return max(prefixes)


def select_latest_versioned_key(
    xml_text: str,
    prefix: str,
    version_pattern: str,
) -> str:
    pattern = re.compile(version_pattern)
    candidates: list[tuple[tuple[int, ...], str]] = []
    for key in _xml_values(xml_text, "Key"):
        if not key.startswith(prefix):
            continue
        match = pattern.search(key)
        if match is not None:
            candidates.append((tuple(int(part) for part in match.groups()), key))
    if not candidates:
        raise ValueError(f"no versioned Firecracker CI object found under {prefix}")
    return max(candidates, key=lambda candidate: candidate[0])[1]


def summarize_boot_times(samples: Sequence[float]) -> dict[str, int | float]:
    values = sorted(float(sample) for sample in samples)
    if not values:
        raise ValueError("at least one boot-time sample is required")
    summary: dict[str, int | float] = {
        "sample_count": len(values),
        "median_boot_time_ms": statistics.median(values),
        "max_boot_time_ms": max(values),
    }
    if len(values) >= 30:
        p95_rank = (95 * len(values) + 99) // 100
        p99_rank = (99 * len(values) + 99) // 100
        summary["p95_boot_time_ms"] = values[p95_rank - 1]
        summary["p99_boot_time_ms"] = values[p99_rank - 1]
    return summary


def _run(
    command: Sequence[str],
    *,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        check=True,
        text=True,
        capture_output=capture_output,
    )


def _s3_listing(prefix: str, *, delimiter: str | None = None) -> str:
    query = {"list-type": "2", "prefix": prefix}
    if delimiter is not None:
        query["delimiter"] = delimiter
    url = f"{S3_BASE}?{urlencode(query)}"
    return _run(
        ["curl", "--fail", "--silent", "--show-error", "--location", url],
        capture_output=True,
    ).stdout


def _download(url: str, destination: Path) -> None:
    _run(
        [
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            url,
            "--output",
            str(destination),
        ]
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_w1_user(rootfs_dir: Path) -> None:
    """Add a deterministic unprivileged W1 account to an extracted guest rootfs."""
    etc_dir = rootfs_dir / "etc"
    etc_dir.mkdir(parents=True, exist_ok=True)
    passwd_path = etc_dir / "passwd"
    group_path = etc_dir / "group"
    passwd_lines: list[str] = []
    group_lines: list[str] = []
    if passwd_path.exists():
        passwd_lines = passwd_path.read_text(encoding="utf-8").splitlines()
    if group_path.exists():
        group_lines = group_path.read_text(encoding="utf-8").splitlines()

    for line in passwd_lines:
        fields = line.split(":")
        if (
            len(fields) >= 7
            and (fields[0] == "tinlance" or fields[2] == "65532")
            and (fields[0] != "tinlance" or fields[2] != "65532")
        ):
            raise ValueError("UID 65532 is already assigned to a different guest account")
    if not any(line.startswith("tinlance:") for line in passwd_lines):
        with passwd_path.open("a", encoding="utf-8") as passwd_file:
            passwd_file.write(
                "tinlance:x:65532:65532:Tinlance W1:/home/tinlance:/usr/sbin/nologin\n"
            )

    for line in group_lines:
        fields = line.split(":")
        if (
            len(fields) >= 3
            and (fields[0] == "tinlance" or fields[2] == "65532")
            and (fields[0] != "tinlance" or fields[2] != "65532")
        ):
            raise ValueError("GID 65532 is already assigned to a different guest group")
    if not any(line.startswith("tinlance:") for line in group_lines):
        with group_path.open("a", encoding="utf-8") as group_file:
            group_file.write("tinlance:x:65532:\n")

    home_dir = rootfs_dir / "home" / "tinlance"
    home_dir.mkdir(parents=True, exist_ok=True)
    home_dir.chmod(0o700)


def guest_init_script(profile: str = "W1") -> str:
    """Return a fail-closed guest init for the selected isolated workload profile."""
    if profile not in {"W1", "W2"}:
        raise ValueError("profile must be W1 or W2")
    script = """#!/bin/sh
set -eu
mount -t proc proc /proc 2>/dev/null || true
mkdir -p /sys
mount -t sysfs sysfs /sys
if touch /etc/tinlance-write-probe 2>/dev/null; then
    echo TINLANCE_ROOTFS_WRITE_UNEXPECTED
    rm -f /etc/tinlance-write-probe
    exit 71
fi
echo TINLANCE_ROOTFS_READ_ONLY_CONFIRMED
for iface_path in /sys/class/net/*; do
    [ -e "$iface_path" ] || continue
    iface=${iface_path##*/}
    if [ "$iface" != "lo" ]; then
        echo TINLANCE_NETWORK_INTERFACE_UNEXPECTED
        exit 72
    fi
done
echo TINLANCE_NO_NIC_CONFIRMED
command -v setpriv >/dev/null 2>&1 || { echo TINLANCE_SETPRIV_MISSING; exit 73; }
mount -t tmpfs -o size=64m,mode=0700,uid=65532,gid=65532,noexec,nosuid,nodev tmpfs /tmp
setpriv --reuid=65532 --regid=65532 --clear-groups /bin/sh -c '
    set -eu
    test "$(id -u)" = 65532
    echo TINLANCE_NONROOT_UID_CONFIRMED
    printf tinlance-gvisor-ok > /tmp/workload.txt
    test "$(cat /tmp/workload.txt)" = tinlance-gvisor-ok
'
echo TINLANCE_W1_WORKLOAD_OK
echo TINLANCE_GUEST_READY
exec /usr/bin/sleep 60
"""
    if profile == "W2":
        script = script.replace(
            "mount -t tmpfs -o size=64m,mode=0700,uid=65532,gid=65532,"
            "noexec,nosuid,nodev tmpfs /tmp",
            "mount -t tmpfs -o size=64m,mode=0700,uid=65532,gid=65532,"
            "noexec,nosuid,nodev tmpfs /tmp\n"
            "mkdir -p /workspace\n"
            "mount -t tmpfs -o size=128m,mode=0700,uid=65532,gid=65532,"
            "noexec,nosuid,nodev tmpfs /workspace\n"
            "echo TINLANCE_W2_WORKSPACE_TMPFS_MOUNTED",
        )
        script = script.replace(
            "setpriv --reuid=65532 --regid=65532 --clear-groups",
            "setpriv --no-new-privs --reuid=65532 --regid=65532 --clear-groups",
        )
        probes = """    command -v mount >/dev/null 2>&1
    grep -Eq "^CapEff:[[:space:]]*0000000000000000$" /proc/self/status
    echo TINLANCE_W2_CAPABILITIES_DROPPED
    grep -Eq "^NoNewPrivs:[[:space:]]*1$" /proc/self/status
    echo TINLANCE_W2_NO_NEW_PRIVS_CONFIRMED
    test -f /etc/shadow
    test ! -r /etc/shadow
    echo TINLANCE_W2_SENSITIVE_FILES_DENIED
    for host_device in /dev/kvm /dev/vhost-net; do
        if [ -e "$host_device" ]; then
            echo "TINLANCE_W2_HOST_DEVICE_UNEXPECTED=$host_device"
            exit 84
        fi
    done
    echo TINLANCE_W2_HOST_DEVICES_ABSENT
    if [ -e /dev/mem ] && [ -r /dev/mem ]; then
        echo TINLANCE_W2_GUEST_MEM_DEVICE_READABLE_UNEXPECTED
        exit 86
    fi
    echo TINLANCE_W2_GUEST_MEM_DEVICE_DENIED
    echo TINLANCE_W2_DEVICE_PROBE_COMPLETED
    for host_socket in \
        /run/docker.sock \
        /var/run/docker.sock \
        /run/containerd/containerd.sock \
        /run/podman/podman.sock \
        /run/crio/crio.sock \
        /run/buildkit/buildkitd.sock; do
        if [ -S "$host_socket" ]; then
            echo "TINLANCE_W2_HOST_SOCKET_UNEXPECTED=$host_socket"
            exit 85
        fi
    done
    echo TINLANCE_W2_HOST_SOCKETS_ABSENT
    echo TINLANCE_W2_SOCKET_PROBE_COMPLETED
    if setpriv --reuid=0 --regid=0 --clear-groups /usr/bin/id >/dev/null 2>&1; then
        echo TINLANCE_W2_PRIVILEGE_ESCALATION_UNEXPECTED
        exit 81
    fi
    echo TINLANCE_W2_PRIVILEGE_ESCALATION_DENIED
    echo TINLANCE_W2_ESCALATION_PROBE_COMPLETED
    if mount -t tmpfs -o size=1m tmpfs /tmp >/dev/null 2>&1; then
        echo TINLANCE_W2_MOUNT_PRIVILEGE_UNEXPECTED
        exit 82
    fi
    echo TINLANCE_W2_MOUNT_PRIVILEGE_DENIED
    echo TINLANCE_W2_MOUNT_PROBE_COMPLETED
    test -e /proc/sys/kernel/hostname
    test ! -w /proc/sys/kernel/hostname
    echo TINLANCE_W2_PROC_SYS_READONLY
    echo TINLANCE_W2_PROC_PROBE_COMPLETED
    echo TINLANCE_W2_HOST_SURFACE_PROBES_OK
    export HOME=/tmp
    export npm_config_cache=/tmp/npm-cache
    command -v git >/dev/null 2>&1
    command -v python3 >/dev/null 2>&1
    command -v node >/dev/null 2>&1
    command -v npm >/dev/null 2>&1
    test -x /opt/tinlance-fixture/run-workspace.sh
    if /opt/tinlance-fixture/run-workspace.sh; then
        echo TINLANCE_W2_DEVELOPER_WORKSPACE_OK
    else
        echo TINLANCE_W2_DEVELOPER_WORKSPACE_FAILED
        exit 83
    fi
"""
        script = script.replace(
            "    echo TINLANCE_NONROOT_UID_CONFIRMED\n",
            "    echo TINLANCE_NONROOT_UID_CONFIRMED\n" + probes,
        )
        if "TINLANCE_W2_WORKSPACE_TMPFS_MOUNTED" not in script:
            raise RuntimeError("W2 guest init did not configure a workspace tmpfs")
    return script


def verify_guest_boot_markers(
    log_text: str,
    profile: str = "W1",
) -> dict[str, bool]:
    if profile not in {"W1", "W2"}:
        raise ValueError("profile must be W1 or W2")
    for marker in GUEST_W2_UNEXPECTED_MARKERS:
        if marker in log_text:
            detail = (
                marker.removeprefix("TINLANCE_W2_")
                .removesuffix("_UNEXPECTED")
                .lower()
                .replace("_", " ")
            )
            raise PermissionError(f"guest host-surface boundary violated: {detail}")
    if GUEST_WRITE_UNEXPECTED_MARKER in log_text:
        raise PermissionError("guest root filesystem unexpectedly accepted a write")
    if GUEST_NIC_UNEXPECTED_MARKER in log_text:
        raise PermissionError("guest unexpectedly exposed a non-loopback network interface")
    if "TINLANCE_SETPRIV_MISSING" in log_text:
        raise RuntimeError("guest image does not provide setpriv for the non-root W1 workload")
    if "TINLANCE_SYSFS_MOUNT_FAILED" in log_text:
        raise RuntimeError("guest could not mount sysfs to verify network interfaces")
    required = {
        "rootfs_read_only_confirmed": GUEST_READ_ONLY_MARKER,
        "no_non_loopback_network_interfaces": GUEST_NO_NIC_MARKER,
        "nonroot_uid_confirmed": "TINLANCE_NONROOT_UID_CONFIRMED",
        "w1_workload_passed": "TINLANCE_W1_WORKLOAD_OK",
        "guest_ready": GUEST_READY_MARKER,
    }
    if profile == "W2":
        required.update(
            {
                "capabilities_dropped": "TINLANCE_W2_CAPABILITIES_DROPPED",
                "no_new_privileges": "TINLANCE_W2_NO_NEW_PRIVS_CONFIRMED",
                "sensitive_files_denied": "TINLANCE_W2_SENSITIVE_FILES_DENIED",
                "host_devices_absent": "TINLANCE_W2_HOST_DEVICES_ABSENT",
                "guest_mem_device_denied": "TINLANCE_W2_GUEST_MEM_DEVICE_DENIED",
                "host_sockets_absent": "TINLANCE_W2_HOST_SOCKETS_ABSENT",
                "privilege_escalation_denied": "TINLANCE_W2_PRIVILEGE_ESCALATION_DENIED",
                "mount_privilege_denied": "TINLANCE_W2_MOUNT_PRIVILEGE_DENIED",
                "proc_sys_readonly": "TINLANCE_W2_PROC_SYS_READONLY",
                "host_surface_probes_passed": "TINLANCE_W2_HOST_SURFACE_PROBES_OK",
                "workspace_tmpfs_mounted": "TINLANCE_W2_WORKSPACE_TMPFS_MOUNTED",
                "npm_install_passed": "TINLANCE_W2_NPM_INSTALL_OK",
                "developer_workspace_passed": "TINLANCE_W2_DEVELOPER_WORKSPACE_OK",
                "git_version_reported": "TINLANCE_W2_GIT_VERSION=",
                "python_version_reported": "TINLANCE_W2_PYTHON_VERSION=",
                "node_version_reported": "TINLANCE_W2_NODE_VERSION=",
                "npm_version_reported": "TINLANCE_W2_NPM_VERSION=",
                "package_manifest_reported": "TINLANCE_W2_PACKAGE_MANIFEST_SHA256=",
                "npm_lock_sha256_reported": "TINLANCE_W2_NPM_LOCK_SHA256=",
            }
        )
    missing = [name for name, marker in required.items() if marker not in log_text]
    if profile == "W2":
        for name, marker in (
            ("git_version_reported", "TINLANCE_W2_GIT_VERSION="),
            ("python_version_reported", "TINLANCE_W2_PYTHON_VERSION="),
            ("node_version_reported", "TINLANCE_W2_NODE_VERSION="),
            ("npm_version_reported", "TINLANCE_W2_NPM_VERSION="),
        ):
            if re.search(rf"{re.escape(marker)}\S+", log_text) is None:
                missing.append(name)
        for name, marker in (
            ("package_manifest_reported", "TINLANCE_W2_PACKAGE_MANIFEST_SHA256="),
            ("npm_lock_sha256_reported", "TINLANCE_W2_NPM_LOCK_SHA256="),
        ):
            if re.search(rf"{re.escape(marker)}[a-f0-9]{{64}}(?:\r?\n|$)", log_text) is None:
                missing.append(name)
    if missing:
        raise ValueError(f"guest isolation markers are missing or malformed: {sorted(set(missing))}")
    return {name: True for name in required}


def extract_w2_rootfs_tar(archive_path: Path, destination: Path) -> None:
    """Safely extract the trusted OCI export while rejecting path and link escapes."""
    if not archive_path.is_file():
        raise ValueError("W2 rootfs tar does not exist")
    destination.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive_path, "r:*") as archive:
            members = archive.getmembers()
            for member in members:
                if any(
                    key.startswith(("SCHILY.xattr.", "SCHILY.acl.", "LIBARCHIVE.xattr."))
                    for key in member.pax_headers
                ):
                    raise ValueError(f"unsupported rootfs extended metadata: {member.name}")
                member_path = PurePosixPath(member.name)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise ValueError(f"unsafe rootfs archive path: {member.name}")
                if member.isdev() or member.isfifo():
                    raise ValueError(f"unsupported special file in rootfs archive: {member.name}")
                if member.issym():
                    target = PurePosixPath(member.linkname)
                    if target.is_absolute():
                        if ".." in target.parts:
                            raise ValueError(
                                f"unsafe absolute symlink in rootfs archive: {member.name}"
                            )
                        member.linkname = os.path.relpath(
                            target.as_posix().lstrip("/"),
                            member_path.parent.as_posix(),
                        )
                    else:
                        resolved = os.path.normpath(
                            os.path.join(member_path.parent.as_posix(), member.linkname)
                        )
                        if resolved == ".." or resolved.startswith("../"):
                            raise ValueError(f"unsafe symlink in rootfs archive: {member.name}")
                if member.islnk():
                    target = PurePosixPath(member.linkname)
                    if target.is_absolute() or ".." in target.parts:
                        raise ValueError(f"unsafe hardlink in rootfs archive: {member.name}")
            for member in members:
                member.uid = member.gid = None
                member.uname = member.gname = None
            ordered = sorted(
                members,
                key=lambda item: (
                    0 if item.isdir() else 1 if item.isfile() else 2 if item.issym() else 3
                ),
            )
            archive.extractall(destination, members=ordered, filter="tar")
    except (tarfile.TarError, OSError, ValueError) as error:
        raise ValueError(f"unsafe rootfs archive: {error}") from error


def w2_network_files() -> dict[str, str]:
    """Return valid, newline-terminated guest-local network configuration."""
    return {
        "hosts": "127.0.0.1 localhost\n::1 localhost\n",
        "hostname": "tinlance-w2\n",
        "resolv.conf": "# guest network is disabled\n",
    }


def _prepare_rootfs(
    squashfs_path: Path | None,
    rootfs_path: Path,
    extract_dir: Path,
    profile: str = "W1",
    w2_rootfs_tar: Path | None = None,
) -> None:
    if profile not in {"W1", "W2"}:
        raise ValueError("profile must be W1 or W2")
    if profile == "W2":
        if w2_rootfs_tar is None:
            raise ValueError("W2 rootfs tar is required")
        extract_w2_rootfs_tar(w2_rootfs_tar, extract_dir)
        etc_dir = extract_dir / "etc"
        etc_dir.mkdir(parents=True, exist_ok=True)
        for name, content in w2_network_files().items():
            path = etc_dir / name
            if path.is_symlink() or path.exists():
                path.unlink()
            path.write_text(content, encoding="utf-8")
    else:
        if squashfs_path is None or w2_rootfs_tar is not None:
            raise ValueError("W1 requires the pinned squashfs rootfs only")
        _run(["unsquashfs", "-d", str(extract_dir), str(squashfs_path)])

    init_path = extract_dir / "usr/local/sbin/tinlance-guest-init"
    init_path.parent.mkdir(parents=True, exist_ok=True)
    init_path.write_text(guest_init_script(profile), encoding="utf-8")
    init_path.chmod(0o755)
    ensure_w1_user(extract_dir)
    tmp_dir = extract_dir / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir.chmod(0o1777)
    dev_dir = extract_dir / "dev"
    dev_dir.mkdir(parents=True, exist_ok=True)
    for node, major, minor, mode in (
        ("console", 5, 1, "600"),
        ("null", 1, 3, "666"),
        ("tty", 5, 0, "666"),
    ):
        node_path = dev_dir / node
        if node_path.is_symlink() and not node_path.exists():
            node_path.unlink()
        if not node_path.exists():
            _run(
                [
                    "sudo",
                    "-n",
                    "mknod",
                    "-m",
                    mode,
                    str(node_path),
                    "c",
                    str(major),
                    str(minor),
                ]
            )

    fixture_dir = extract_dir / "opt" / "tinlance-fixture"
    if profile == "W2":
        if not (fixture_dir / "run-workspace.sh").is_file():
            raise ValueError("W2 OCI rootfs is missing the developer-workspace fixture")
        _run(["sudo", "-n", "chown", "-R", "root:root", str(extract_dir)])
        _run(
            [
                "sudo",
                "-n",
                "chown",
                "65532:65532",
                str(extract_dir / "home" / "tinlance"),
            ]
        )
        _run(["sudo", "-n", "chown", "-R", "65532:65532", str(fixture_dir)])
        _run(["sudo", "-n", "chmod", "-R", "a=rX", str(fixture_dir)])
    else:
        _run(["sudo", "-n", "chown", "-R", "root:root", str(extract_dir)])
        _run(
            [
                "sudo",
                "-n",
                "chown",
                "65532:65532",
                str(extract_dir / "home" / "tinlance"),
            ]
        )

    try:
        image_size = "2G" if profile == "W2" else "1G"
        _run(["truncate", "-s", image_size, str(rootfs_path)])
        _run(
            [
                "sudo",
                "-n",
                "mkfs.ext4",
                "-F",
                "-d",
                str(extract_dir),
                str(rootfs_path),
            ]
        )
        _run(["sudo", "-n", "e2fsck", "-fn", str(rootfs_path)])
    finally:
        _run(
            [
                "sudo",
                "-n",
                "chown",
                "-R",
                f"{os.getuid()}:{os.getgid()}",
                str(extract_dir),
            ]
        )


def _api_request(
    socket_path: Path,
    method: str,
    endpoint: str,
    payload: dict[str, object] | None = None,
) -> str:
    command = [
        "sudo",
        "-n",
        "curl",
        "--fail",
        "--silent",
        "--show-error",
        "--unix-socket",
        str(socket_path),
        "-X",
        method,
    ]
    if payload is not None:
        command.extend(
            [
                "--header",
                "Content-Type: application/json",
                "--data-binary",
                json.dumps(payload, separators=(",", ":")),
            ]
        )
    command.append(f"http://localhost{endpoint}")
    return _run(command, capture_output=True).stdout


def _wait_for_socket(socket_path: Path, log_path: Path, timeout_seconds: float = 10) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if socket_path.exists():
            return
        if (
            log_path.exists()
            and "error" in log_path.read_text(encoding="utf-8", errors="replace").lower()
        ):
            break
        time.sleep(0.1)
    log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    raise RuntimeError(f"Firecracker API socket did not appear. VMM log tail:\\n{log[-3000:]}")


def _stop_firecracker(socket_path: Path) -> None:
    subprocess.run(
        ["sudo", "-n", "pkill", "-x", "firecracker"],
        check=False,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["sudo", "-n", "rm", "-f", str(socket_path)],
        check=False,
        capture_output=True,
        text=True,
    )


def _run_guest(
    firecracker_binary: Path,
    kernel_path: Path,
    rootfs_path: Path,
    run_index: int,
    work_dir: Path,
    log_dir: Path,
    timeout_seconds: float,
    profile: str = "W1",
) -> tuple[float, dict[str, str], dict[str, bool]]:
    socket_path = work_dir / f"api-{run_index}.sock"
    log_path = log_dir / f"firecracker-guest-boot-{run_index}.log"
    _stop_firecracker(socket_path)

    try:
        with log_path.open("w", encoding="utf-8") as log_handle:
            subprocess.run(
                [
                    "sudo",
                    "-n",
                    "-b",
                    str(firecracker_binary),
                    "--api-sock",
                    str(socket_path),
                ],
                check=True,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                text=True,
            )
            _wait_for_socket(socket_path, log_path)

            version = json.loads(_api_request(socket_path, "GET", "/version"))
            if version.get("firecracker_version") != FIRECRACKER_VERSION:
                raise RuntimeError("Firecracker VMM version does not match the pinned release")
            _api_request(
                socket_path,
                "PUT",
                "/machine-config",
                machine_config_for_profile(profile),
            )
            _api_request(
                socket_path,
                "PUT",
                "/boot-source",
                {
                    "kernel_image_path": str(kernel_path),
                    "boot_args": (
                        "console=ttyS0 reboot=k panic=1 "
                        "root=/dev/vda ro init=/usr/local/sbin/tinlance-guest-init"
                    ),
                },
            )
            _api_request(
                socket_path,
                "PUT",
                "/drives/rootfs",
                {
                    "drive_id": "rootfs",
                    "path_on_host": str(rootfs_path),
                    "is_root_device": True,
                    "is_read_only": True,
                },
            )
            time.sleep(0.015)
            started = time.monotonic()
            _api_request(socket_path, "PUT", "/actions", {"action_type": "InstanceStart"})

            deadline = started + timeout_seconds
            while time.monotonic() < deadline:
                log_text = log_path.read_text(encoding="utf-8", errors="replace")
                if (
                    GUEST_WRITE_UNEXPECTED_MARKER in log_text
                    or GUEST_NIC_UNEXPECTED_MARKER in log_text
                    or "TINLANCE_SYSFS_MOUNT_FAILED" in log_text
                    or any(marker in log_text for marker in GUEST_W2_UNEXPECTED_MARKERS)
                ):
                    verify_guest_boot_markers(log_text, profile)
                if GUEST_READY_MARKER in log_text:
                    guest_isolation = verify_guest_boot_markers(log_text, profile)
                    return (time.monotonic() - started) * 1000, version, guest_isolation
                running = subprocess.run(
                    ["sudo", "-n", "pgrep", "-x", "firecracker"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if running.returncode != 0:
                    raise RuntimeError(
                        "Firecracker exited before guest-ready marker. "
                        f"VMM log tail:\\n{log_text[-5000:]}"
                    )
                time.sleep(0.1)

            log_text = log_path.read_text(encoding="utf-8", errors="replace")
            raise TimeoutError(
                f"guest did not reach init shell within {timeout_seconds}s. "
                f"VMM log tail:\\n{log_text[-5000:]}"
            )
    finally:
        _stop_firecracker(socket_path)


def load_asset_manifest(path: Path, architecture: str) -> GuestAssetManifest:
    data: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or type(data.get("schema_version")) is not int:
        raise ValueError("unsupported Firecracker guest asset manifest schema")
    if data.get("schema_version") != 1:
        raise ValueError("unsupported Firecracker guest asset manifest schema")
    manifest = cast(GuestAssetManifest, data)
    if manifest.get("architecture") != architecture:
        raise ValueError("guest asset manifest architecture does not match the runner")
    artifact_prefix = manifest.get("artifact_prefix", "")
    if not isinstance(artifact_prefix, str) or not re.fullmatch(
        r"firecracker-ci/\d{8}-[^/]+/",
        artifact_prefix,
    ):
        raise ValueError("guest asset manifest has an invalid upstream artifact prefix")
    expected_prefix = f"{artifact_prefix}{architecture}/"
    for key_name, pattern in (
        ("kernel_key", r"vmlinux-\d+\.\d+\.\d+$"),
        ("rootfs_key", r"ubuntu-\d+\.\d+\.squashfs$"),
    ):
        key = manifest.get(key_name, "")
        if (
            not isinstance(key, str)
            or not key.startswith(expected_prefix)
            or key.count("/") != expected_prefix.count("/")
        ):
            raise ValueError(f"guest asset manifest {key_name} is outside its artifact prefix")
        if not re.search(pattern, key):
            raise ValueError(f"guest asset manifest {key_name} has an invalid filename")
    for hash_name in ("kernel_sha256", "rootfs_squashfs_sha256"):
        digest = manifest.get(hash_name, "")
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError(f"guest asset manifest {hash_name} is invalid")
    return manifest


def _discover_asset_manifest(work_dir: Path, architecture: str) -> GuestAssetManifest:
    prefix_listing = _s3_listing("firecracker-ci/", delimiter="/")
    artifact_prefix = parse_latest_artifact_prefix(prefix_listing)
    architecture_prefix = f"{artifact_prefix}{architecture}/"
    kernel_listing = _s3_listing(f"{architecture_prefix}vmlinux-")
    kernel_key = select_latest_versioned_key(
        kernel_listing,
        architecture_prefix,
        r"vmlinux-(\d+)\.(\d+)\.(\d+)$",
    )
    rootfs_listing = _s3_listing(f"{architecture_prefix}ubuntu-")
    rootfs_key = select_latest_versioned_key(
        rootfs_listing,
        architecture_prefix,
        r"ubuntu-(\d+)\.(\d+)\.squashfs$",
    )
    kernel_path = work_dir / "guest-vmlinux"
    squashfs_path = work_dir / "guest-rootfs.squashfs"
    _download(f"{S3_BASE}/{kernel_key}", kernel_path)
    _download(f"{S3_BASE}/{rootfs_key}", squashfs_path)
    return {
        "schema_version": 1,
        "architecture": architecture,
        "source": f"{S3_BASE}/",
        "discovered_at": datetime.now(UTC).date().isoformat(),
        "artifact_prefix": artifact_prefix,
        "kernel_key": kernel_key,
        "kernel_sha256": _sha256(kernel_path),
        "rootfs_key": rootfs_key,
        "rootfs_squashfs_sha256": _sha256(squashfs_path),
    }


def _download_pinned_guest_assets(
    work_dir: Path,
    manifest: GuestAssetManifest,
    profile: str = "W1",
    w2_rootfs_tar: Path | None = None,
) -> dict[str, object]:
    kernel_path = work_dir / "guest-vmlinux"
    squashfs_path = work_dir / "guest-rootfs.squashfs"
    rootfs_path = work_dir / "guest-rootfs.ext4"
    _download(f"{S3_BASE}/{manifest['kernel_key']}", kernel_path)
    kernel_sha256 = _sha256(kernel_path)
    if kernel_sha256 != manifest["kernel_sha256"]:
        raise ValueError("downloaded guest kernel SHA-256 does not match the pinned manifest")

    rootfs_squashfs_sha256: str | None = None
    if profile == "W1":
        if w2_rootfs_tar is not None:
            raise ValueError("W1 cannot accept a W2 OCI rootfs tar")
        _download(f"{S3_BASE}/{manifest['rootfs_key']}", squashfs_path)
        rootfs_squashfs_sha256 = _sha256(squashfs_path)
        if rootfs_squashfs_sha256 != manifest["rootfs_squashfs_sha256"]:
            raise ValueError("downloaded guest rootfs SHA-256 does not match the pinned manifest")
        _prepare_rootfs(squashfs_path, rootfs_path, work_dir / "squashfs-root", profile)
    elif profile == "W2":
        if w2_rootfs_tar is None:
            raise ValueError("W2 requires the content-addressed OCI rootfs tar")
        _prepare_rootfs(
            None,
            rootfs_path,
            work_dir / "oci-rootfs",
            profile,
            w2_rootfs_tar,
        )
    else:
        raise ValueError("profile must be W1 or W2")

    return {
        **manifest,
        "kernel_path": kernel_path,
        "squashfs_path": squashfs_path if profile == "W1" else None,
        "rootfs_path": rootfs_path,
        "kernel_sha256": kernel_sha256,
        "rootfs_squashfs_sha256": rootfs_squashfs_sha256,
        "w2_rootfs_tar_sha256": (_sha256(w2_rootfs_tar) if w2_rootfs_tar is not None else None),
        "rootfs_ext4_sha256": _sha256(rootfs_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Boot a network-disconnected Firecracker guest on an ephemeral KVM runner."
    )
    parser.add_argument("--firecracker", type=Path)
    parser.add_argument("--firecracker-archive", type=Path)
    parser.add_argument(
        "--assets-manifest",
        type=Path,
        default=(
            Path(__file__).resolve().parents[1] / "tests/fixtures/firecracker-guest-assets.json"
        ),
    )
    parser.add_argument("--discover-latest", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--log-dir", type=Path)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--profile", choices=("W1", "W2"), default="W1")
    parser.add_argument("--w2-rootfs-tar", type=Path)
    parser.add_argument("--w2-image-id")
    parser.add_argument("--w2-base-image-digest")
    parser.add_argument("--timeout-seconds", type=float, default=45)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.discover_latest:
        with tempfile.TemporaryDirectory(prefix="fc-asset-discovery-", dir="/tmp") as temporary:
            manifest = _discover_asset_manifest(Path(temporary), platform.machine())
            args.output.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        return 0

    if args.runs < 1:
        parser.error("--runs must be at least 1")
    if args.profile == "W2":
        if args.w2_rootfs_tar is None or not args.w2_rootfs_tar.is_file():
            parser.error("--profile W2 requires an existing --w2-rootfs-tar")
        if args.w2_image_id is None or not _OCI_IMAGE_ID.fullmatch(args.w2_image_id):
            parser.error("--profile W2 requires a content-addressed --w2-image-id")
        if args.w2_base_image_digest is None or not _OCI_IMAGE_DIGEST.fullmatch(
            args.w2_base_image_digest
        ):
            parser.error("--profile W2 requires a digest-pinned --w2-base-image-digest")
    elif any((args.w2_rootfs_tar, args.w2_image_id, args.w2_base_image_digest)):
        parser.error("W2 OCI rootfs arguments are only valid with --profile W2")
    if args.firecracker is None or not args.firecracker.is_file():
        parser.error("--firecracker must point to the verified Firecracker binary")
    if args.firecracker_archive is None or not args.firecracker_archive.is_file():
        parser.error("--firecracker-archive must point to the downloaded release archive")
    archive_sha256 = _sha256(args.firecracker_archive)
    if archive_sha256 != FIRECRACKER_ARCHIVE_SHA256:
        raise ValueError("Firecracker release archive SHA-256 does not match the pinned release")

    manifest = load_asset_manifest(args.assets_manifest, platform.machine())
    log_dir = args.log_dir or args.output.parent / "firecracker-guest-boot-logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="fc-guest-boot-", dir="/tmp") as temporary:
        work_dir = Path(temporary)
        firecracker_binary = work_dir / "firecracker"
        shutil.copy2(args.firecracker, firecracker_binary)
        firecracker_binary.chmod(0o755)
        assets = _download_pinned_guest_assets(
            work_dir,
            manifest,
            args.profile,
            args.w2_rootfs_tar,
        )
        kernel_path = assets["kernel_path"]
        rootfs_path = assets["rootfs_path"]
        if not isinstance(kernel_path, Path) or not isinstance(rootfs_path, Path):
            raise RuntimeError("pinned guest asset loader returned invalid paths")

        samples: list[float] = []
        guest_isolation_samples: list[dict[str, bool]] = []
        firecracker_version: dict[str, str] = {}
        for run_index in range(1, args.runs + 1):
            boot_time_ms, version, guest_isolation = _run_guest(
                firecracker_binary,
                kernel_path,
                rootfs_path,
                run_index,
                work_dir,
                log_dir,
                args.timeout_seconds,
                args.profile,
            )
            samples.append(boot_time_ms)
            guest_isolation_samples.append(guest_isolation)
            firecracker_version = version

        summary = summarize_boot_times(samples)
        report = {
            "status": "passed",
            "execution_mode": "direct-vmm-ephemeral-smoke",
            "jailer_executed": False,
            "production_certification": False,
            "guest_network_configured": False,
            "guest_rootfs_read_only": all(
                sample["rootfs_read_only_confirmed"] for sample in guest_isolation_samples
            ),
            "guest_isolation_checks": guest_isolation_samples,
            "guest_workload": {
                "profile": (
                    "W1-minimal-agent"
                    if args.profile == "W1"
                    else "W2-developer-workspace-and-host-surface"
                ),
                "network": "none",
                "rootfs_read_only": True,
                "uid": 65532,
                "gid": 65532,
                "tmpfs": "/tmp:rw,size=64m,mode=0700,uid=65532,gid=65532",
                "workload_marker": "TINLANCE_W1_WORKLOAD_OK",
                "host_surface_marker": (
                    "TINLANCE_W2_HOST_SURFACE_PROBES_OK" if args.profile == "W2" else None
                ),
                "developer_workspace": args.profile == "W2",
                "workspace_tmpfs": (
                    "/workspace:rw,size=128m,mode=0700,uid=65532,gid=65532,noexec,nosuid,nodev"
                    if args.profile == "W2"
                    else None
                ),
                "developer_workspace_marker": (
                    "TINLANCE_W2_DEVELOPER_WORKSPACE_OK" if args.profile == "W2" else None
                ),
            },
            "guest_ready_marker": GUEST_READY_MARKER,
            "boot_time_measurement": (
                "elapsed time from immediately before the InstanceStart API request "
                f"until the guest completes the {args.profile} workload and emits its ready marker "
                "on the serial console"
            ),
            "firecracker_version": firecracker_version.get("firecracker_version"),
            "firecracker_archive_sha256": archive_sha256,
            "guest_asset_manifest_sha256": _sha256(args.assets_manifest),
            "guest_architecture": platform.machine(),
            "host_kernel_release": platform.release(),
            "upstream_ci_artifact_prefix": assets["artifact_prefix"],
            "guest_kernel_key": assets["kernel_key"],
            "guest_rootfs_key": assets["rootfs_key"] if args.profile == "W1" else None,
            "guest_rootfs_source": (
                "pinned-upstream-squashfs"
                if args.profile == "W1"
                else "content-addressed-oci-export"
            ),
            "w2_base_image_digest": args.w2_base_image_digest,
            "w2_image_id": args.w2_image_id,
            "w2_rootfs_tar_sha256": assets["w2_rootfs_tar_sha256"],
            "guest_kernel_sha256": assets["kernel_sha256"],
            "guest_rootfs_squashfs_sha256": assets["rootfs_squashfs_sha256"],
            "guest_rootfs_ext4_sha256": assets["rootfs_ext4_sha256"],
            "boot_time_samples_ms": samples,
            **summary,
            "captured_at": datetime.now(UTC).isoformat(),
        }
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
