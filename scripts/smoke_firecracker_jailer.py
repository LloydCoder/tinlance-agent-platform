from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from scripts.smoke_firecracker_guest_boot import (
    _OCI_IMAGE_DIGEST,
    _OCI_IMAGE_ID,
    FIRECRACKER_ARCHIVE_SHA256,
    GUEST_NIC_UNEXPECTED_MARKER,
    GUEST_READY_MARKER,
    GUEST_W2_UNEXPECTED_MARKERS,
    GUEST_WRITE_UNEXPECTED_MARKER,
    _api_request,
    _download_pinned_guest_assets,
    load_asset_manifest,
    machine_config_for_profile,
    summarize_boot_times,
    verify_guest_boot_markers,
)

CGROUP_LIMITS_BY_PROFILE = {
    "W1": (
        ("memory.max", "805306368"),
        ("pids.max", "128"),
        ("cpu.max", "100000 100000"),
    ),
    "W2": (
        ("memory.max", "3221225472"),
        ("pids.max", "128"),
        ("cpu.max", "200000 100000"),
    ),
}


def cgroup_limits_for_profile(profile: str) -> tuple[tuple[str, str], ...]:
    try:
        return CGROUP_LIMITS_BY_PROFILE[profile]
    except KeyError as error:
        raise ValueError("profile must be W1 or W2") from error


def build_jailer_command(
    *,
    jailer_binary: str,
    firecracker_binary: str,
    jailer_id: str,
    uid: int,
    gid: int,
    chroot_base_dir: str,
    profile: str = "W1",
    network_namespace_path: str | None = None,
) -> list[str]:
    if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", jailer_id):
        raise ValueError("jailer identifier must be 1-64 safe alphanumeric/hyphen characters")
    if uid <= 0 or gid <= 0:
        raise ValueError("jailer must run under a non-root uid and gid")
    for path in (jailer_binary, firecracker_binary, chroot_base_dir, network_namespace_path):
        if path is not None and not Path(path).is_absolute():
            raise ValueError(
                "jailer executable, chroot and network namespace paths must be absolute"
            )

    command = [
        "sudo",
        "-n",
        jailer_binary,
        "--id",
        jailer_id,
        "--exec-file",
        firecracker_binary,
        "--uid",
        str(uid),
        "--gid",
        str(gid),
        "--cgroup-version",
        "2",
    ]
    if network_namespace_path is not None:
        command.extend(["--netns", network_namespace_path])
    for name, value in cgroup_limits_for_profile(profile):
        command.extend(["--cgroup", f"{name}={value}"])
    command.extend(
        [
            "--chroot-base-dir",
            chroot_base_dir,
            "--new-pid-ns",
            "--",
            "--api-sock",
            "/run/firecracker.socket",
        ]
    )
    return command


def validate_jailer_profile_inputs(
    *,
    profile: str,
    w2_rootfs_tar: Path | None,
    w2_image_id: str | None,
    w2_base_image_digest: str | None,
    network_namespace_path: Path | None,
) -> None:
    """Fail closed unless the selected jailer profile has its required immutable inputs."""
    if profile not in {"W1", "W2"}:
        raise ValueError("profile must be W1 or W2")
    if profile == "W1":
        if any((w2_rootfs_tar, w2_image_id, w2_base_image_digest, network_namespace_path)):
            raise ValueError("W2 rootfs inputs are only valid with the W2 profile")
        return
    if w2_rootfs_tar is None or not w2_rootfs_tar.is_file():
        raise ValueError("a normalized W2 rootfs tar is required")
    if (
        network_namespace_path is None
        or not network_namespace_path.is_absolute()
        or network_namespace_path.is_symlink()
        or not network_namespace_path.exists()
    ):
        raise ValueError("a trusted W2 network namespace handle is required")
    if w2_image_id is None or not _OCI_IMAGE_ID.fullmatch(w2_image_id):
        raise ValueError("a content-addressed W2 image ID is required")
    if w2_base_image_digest is None or not _OCI_IMAGE_DIGEST.fullmatch(w2_base_image_digest):
        raise ValueError("a digest-pinned W2 base image is required")


def _parse_proc_status(status_text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in status_text.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            fields[key] = value.strip()
    return fields


def verify_jailer_process_evidence(
    *,
    status_text: str,
    cgroup_text: str,
    expected_uid: int,
    expected_gid: int,
    host_mount_namespace: str,
    process_mount_namespace: str,
    host_pid_namespace: str,
    process_pid_namespace: str,
    expected_chroot_identity: str,
    process_root_identity: str,
    thread_seccomp_modes: Sequence[int],
) -> dict[str, int | bool | str | list[int]]:
    status = _parse_proc_status(status_text)
    try:
        uid_values = [int(value) for value in status["Uid"].split()]
        gid_values = [int(value) for value in status["Gid"].split()]
        seccomp_mode = int(status["Seccomp"])
        no_new_privs = status["NoNewPrivs"] == "1"
        capabilities_effective = status["CapEff"]
        pid_values = [int(value) for value in status["NSpid"].split()]
    except (KeyError, ValueError) as exc:
        raise PermissionError("jailer process security evidence is incomplete") from exc

    if not uid_values or any(value != expected_uid for value in uid_values):
        raise PermissionError(
            "jailer process uid does not match the dedicated unprivileged identity"
        )
    if not gid_values or any(value != expected_gid for value in gid_values):
        raise PermissionError(
            "jailer process gid does not match the dedicated unprivileged identity"
        )
    if seccomp_mode != 2:
        raise PermissionError("jailer process does not have seccomp filter mode enabled")
    if not thread_seccomp_modes or any(mode != 2 for mode in thread_seccomp_modes):
        raise PermissionError("one or more Firecracker threads lack seccomp filter mode")
    if not no_new_privs:
        raise PermissionError("jailer process does not have no_new_privs enabled")
    if capabilities_effective != "0000000000000000":
        raise PermissionError("jailer process retains effective Linux capabilities")
    if len(pid_values) < 2 or pid_values[-1] != 1:
        raise PermissionError("jailer process is not isolated in a new PID namespace")
    if host_mount_namespace == process_mount_namespace:
        raise PermissionError("jailer process is not isolated in a mount namespace")
    if host_pid_namespace == process_pid_namespace:
        raise PermissionError("jailer process is not isolated in a PID namespace")
    if process_root_identity != expected_chroot_identity:
        raise PermissionError("jailer process root inode does not match its dedicated chroot")

    cgroup_v2_path = next(
        (
            line.partition("::")[2]
            for line in cgroup_text.splitlines()
            if "::" in line and line.partition("::")[0] == "0"
        ),
        "",
    )
    if not cgroup_v2_path.startswith("/") or cgroup_v2_path == "/":
        raise PermissionError("jailer process is not assigned to a dedicated cgroup v2")
    if ".." in Path(cgroup_v2_path).parts:
        raise PermissionError("jailer cgroup path is invalid")

    return {
        "uid": expected_uid,
        "gid": expected_gid,
        "seccomp_mode": seccomp_mode,
        "thread_seccomp_modes": list(thread_seccomp_modes),
        "no_new_privs": no_new_privs,
        "capabilities_effective": capabilities_effective,
        "pid_namespace_isolated": True,
        "mount_namespace_isolated": True,
        "chroot_identity": process_root_identity,
        "cgroup_path": cgroup_v2_path,
    }


def verify_jailer_network_namespace_evidence(
    *,
    host_network_namespace: str,
    process_network_namespace: str,
    process_network_interfaces: Sequence[str],
) -> dict[str, bool | list[str] | str]:
    """Require a distinct Firecracker network namespace with loopback only."""
    if (
        not host_network_namespace
        or not process_network_namespace
        or host_network_namespace == process_network_namespace
    ):
        raise PermissionError("jailer process is not isolated in a separate network namespace")
    interfaces = sorted(set(process_network_interfaces))
    if interfaces != ["lo"]:
        raise PermissionError(
            f"jailer network namespace exposes non-loopback interfaces: {interfaces}"
        )
    return {
        "network_namespace_isolated": True,
        "host_network_namespace": host_network_namespace,
        "process_network_namespace": process_network_namespace,
        "network_interfaces": interfaces,
    }


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


def _wait_for_path(
    path: Path,
    log_path: Path,
    timeout: float,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        socket_probe = subprocess.run(
            ["sudo", "-n", "test", "-S", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
        if socket_probe.returncode == 0:
            return
        time.sleep(0.1)
    log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    raise RuntimeError(f"jailer did not create the Firecracker API socket: {log[-5000:]}")


def _find_firecracker_pid(
    jailer_id: str,
    expected_uid: int,
    timeout_seconds: float = 10,
) -> int:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                comm = (entry / "comm").read_text(encoding="utf-8").strip()
                status = _parse_proc_status((entry / "status").read_text(encoding="utf-8"))
                cgroup_text = (entry / "cgroup").read_text(encoding="utf-8")
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            uid_values = status.get("Uid", "").split()
            if (
                comm == "firecracker"
                and uid_values
                and int(uid_values[0]) == expected_uid
                and jailer_id in cgroup_text
            ):
                return int(entry.name)
        time.sleep(0.1)
    raise RuntimeError(
        "jailed Firecracker process could not be located by its dedicated uid and cgroup identity"
    )


def _readlink_as_root(path: Path) -> str:
    return _run(
        ["sudo", "-n", "readlink", str(path)],
        capture_output=True,
    ).stdout.strip()


def _stat_identity_as_root(path: Path) -> str:
    return _run(
        ["sudo", "-n", "stat", "-Lc", "%d:%i", str(path)],
        capture_output=True,
    ).stdout.strip()


def _read_thread_seccomp_modes(pid: int) -> tuple[int, ...]:
    task_dir = Path("/proc") / str(pid) / "task"
    modes: list[int] = []
    for thread_dir in task_dir.iterdir():
        status_text = _run(
            ["sudo", "-n", "cat", str(thread_dir / "status")],
            capture_output=True,
        ).stdout
        status = _parse_proc_status(status_text)
        modes.append(int(status["Seccomp"]))
    return tuple(modes)


def _read_process_network_interfaces(pid: int) -> tuple[str, ...]:
    network_dev = Path("/proc") / str(pid) / "net/dev"
    content = _run(["sudo", "-n", "cat", str(network_dev)], capture_output=True).stdout
    return tuple(line.partition(":")[0].strip() for line in content.splitlines()[2:] if ":" in line)


def _read_process_evidence(
    pid: int,
    uid: int,
    gid: int,
    expected_chroot_root: Path,
    *,
    require_network_namespace: bool = False,
) -> dict[str, int | bool | str | list[int] | list[str]]:
    proc = Path("/proc") / str(pid)
    evidence: dict[str, int | bool | str | list[int] | list[str]] = verify_jailer_process_evidence(
        status_text=(proc / "status").read_text(encoding="utf-8"),
        cgroup_text=(proc / "cgroup").read_text(encoding="utf-8"),
        expected_uid=uid,
        expected_gid=gid,
        host_mount_namespace=os.readlink("/proc/self/ns/mnt"),
        process_mount_namespace=_readlink_as_root(proc / "ns/mnt"),
        host_pid_namespace=os.readlink("/proc/self/ns/pid"),
        process_pid_namespace=_readlink_as_root(proc / "ns/pid"),
        expected_chroot_identity=_stat_identity_as_root(expected_chroot_root),
        process_root_identity=_stat_identity_as_root(proc / "root"),
        thread_seccomp_modes=_read_thread_seccomp_modes(pid),
    )
    if require_network_namespace:
        evidence.update(
            verify_jailer_network_namespace_evidence(
                host_network_namespace=os.readlink("/proc/self/ns/net"),
                process_network_namespace=_readlink_as_root(proc / "ns/net"),
                process_network_interfaces=_read_process_network_interfaces(pid),
            )
        )
    return evidence


def _verify_cgroup_limits(cgroup_path: str, profile: str = "W1") -> dict[str, str]:
    root = Path("/sys/fs/cgroup").resolve()
    candidate = (root / cgroup_path.lstrip("/")).resolve()
    if root not in candidate.parents:
        raise PermissionError("jailer cgroup escaped the cgroup v2 mount")
    expected = dict(cgroup_limits_for_profile(profile))
    observed: dict[str, str] = {}
    for filename, expected_value in expected.items():
        path = candidate / filename
        value = path.read_text(encoding="utf-8").strip()
        if value != expected_value:
            raise PermissionError(f"jailer cgroup {filename} does not match its configured limit")
        observed[filename] = value
    return observed


def _is_process_alive(pid: int) -> bool:
    stat_path = Path("/proc") / str(pid) / "stat"
    try:
        stat = stat_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return False
    state = stat.rsplit(")", 1)[-1].strip().split(maxsplit=1)[0]
    return state != "Z"


def _stop_process(
    process: subprocess.Popen[str],
    firecracker_pid: int | None,
) -> None:
    if firecracker_pid is not None and _is_process_alive(firecracker_pid):
        subprocess.run(
            ["sudo", "-n", "kill", "-TERM", str(firecracker_pid)],
            check=False,
            capture_output=True,
            text=True,
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and _is_process_alive(firecracker_pid):
            time.sleep(0.1)
        if _is_process_alive(firecracker_pid):
            subprocess.run(
                ["sudo", "-n", "kill", "-KILL", str(firecracker_pid)],
                check=False,
                capture_output=True,
                text=True,
            )
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=2)


def _stage_guest_assets(
    chroot_root: Path,
    kernel_source: Path,
    rootfs_source: Path,
    uid: int,
    gid: int,
) -> tuple[str, str]:
    guest_dir = chroot_root / "var/lib/firecracker"
    _run(["sudo", "-n", "mkdir", "-p", str(guest_dir)])
    kernel_target = guest_dir / "vmlinux"
    rootfs_target = guest_dir / "rootfs.ext4"
    _run(
        [
            "sudo",
            "-n",
            "install",
            "-o",
            str(uid),
            "-g",
            str(gid),
            "-m",
            "0400",
            str(kernel_source),
            str(kernel_target),
        ]
    )
    _run(
        [
            "sudo",
            "-n",
            "install",
            "-o",
            str(uid),
            "-g",
            str(gid),
            "-m",
            "0400",
            str(rootfs_source),
            str(rootfs_target),
        ]
    )
    return "/var/lib/firecracker/vmlinux", "/var/lib/firecracker/rootfs.ext4"


def _run_jailer_guest(
    *,
    jailer_binary: Path,
    firecracker_binary: Path,
    jailer_id: str,
    uid: int,
    gid: int,
    chroot_base_dir: Path,
    kernel_path: Path,
    rootfs_path: Path,
    log_path: Path,
    timeout_seconds: float,
    profile: str = "W1",
    network_namespace_path: Path | None = None,
) -> tuple[
    float,
    dict[str, int | bool | str | list[int] | list[str]],
    dict[str, str],
    dict[str, str],
    dict[str, bool],
]:
    command = build_jailer_command(
        jailer_binary=str(jailer_binary),
        firecracker_binary=str(firecracker_binary),
        jailer_id=jailer_id,
        uid=uid,
        gid=gid,
        chroot_base_dir=str(chroot_base_dir),
        profile=profile,
        network_namespace_path=(
            str(network_namespace_path) if network_namespace_path is not None else None
        ),
    )
    chroot_root = chroot_base_dir / "firecracker" / jailer_id / "root"
    socket_path = chroot_root / "run/firecracker.socket"
    process: subprocess.Popen[str] | None = None
    firecracker_pid: int | None = None
    cgroup_path: str | None = None

    try:
        with log_path.open("w", encoding="utf-8") as log_handle:
            process = subprocess.Popen(
                command,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            _wait_for_path(socket_path, log_path, timeout_seconds)
            firecracker_pid = _find_firecracker_pid(jailer_id, uid)
            process_cgroup = (Path("/proc") / str(firecracker_pid) / "cgroup").read_text(
                encoding="utf-8"
            )
            cgroup_path = next(
                (
                    line.partition("::")[2]
                    for line in process_cgroup.splitlines()
                    if "::" in line and line.partition("::")[0] == "0"
                ),
                "",
            )
            if not cgroup_path.startswith("/") or cgroup_path == "/":
                raise PermissionError("jailed Firecracker has no dedicated cgroup v2")
            if jailer_id not in Path(cgroup_path).parts:
                raise PermissionError(
                    "jailed Firecracker cgroup does not contain its unique jailer id"
                )
            guest_kernel, guest_rootfs = _stage_guest_assets(
                chroot_root,
                kernel_path,
                rootfs_path,
                uid,
                gid,
            )

            version = json.loads(_api_request(socket_path, "GET", "/version"))
            if version.get("firecracker_version") != "1.17.0":
                raise RuntimeError("jailed Firecracker version does not match the pinned release")
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
                    "kernel_image_path": guest_kernel,
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
                    "path_on_host": guest_rootfs,
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
                    process_evidence = _read_process_evidence(
                        firecracker_pid,
                        uid,
                        gid,
                        chroot_root,
                        require_network_namespace=profile == "W2",
                    )
                    cgroup_evidence = _verify_cgroup_limits(cgroup_path, profile)
                    return (
                        (time.monotonic() - started) * 1000,
                        process_evidence,
                        cgroup_evidence,
                        version,
                        guest_isolation,
                    )
                if not _is_process_alive(firecracker_pid):
                    raise RuntimeError(
                        f"jailed Firecracker exited before guest readiness: {log_text[-5000:]}"
                    )
                time.sleep(0.1)
            log_text = log_path.read_text(encoding="utf-8", errors="replace")
            raise TimeoutError(f"jailed guest did not reach readiness: {log_text[-5000:]}")
    finally:
        active_exception = sys.exc_info()[1]
        cleanup_errors: list[str] = []
        if process is not None:
            try:
                _stop_process(process, firecracker_pid)
            except Exception as error:
                cleanup_errors.append(f"jailer process cleanup failed: {error}")

        cgroup_dir = (
            Path("/sys/fs/cgroup") / cgroup_path.lstrip("/")
            if cgroup_path is not None
            else Path("/sys/fs/cgroup/firecracker") / jailer_id
        )
        if cgroup_dir.exists():
            result = subprocess.run(
                ["sudo", "-n", "rmdir", "--", str(cgroup_dir)],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0 or cgroup_dir.exists():
                cleanup_errors.append(
                    f"jailer cgroup was not removed: {cgroup_dir}: {result.stderr.strip()}"
                )

        jailer_root = chroot_base_dir / "firecracker" / jailer_id
        result = subprocess.run(
            ["sudo", "-n", "rm", "-rf", "--", str(jailer_root)],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0 or jailer_root.exists():
            cleanup_errors.append(
                f"jailer chroot was not removed: {jailer_root}: {result.stderr.strip()}"
            )

        if cleanup_errors:
            cleanup_error = RuntimeError("; ".join(cleanup_errors))
            if active_exception is not None:
                raise cleanup_error from active_exception
            raise cleanup_error


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a Firecracker guest boot through the upstream jailer.",
    )
    parser.add_argument("--jailer", required=True, type=Path)
    parser.add_argument("--firecracker", required=True, type=Path)
    parser.add_argument("--firecracker-archive", required=True, type=Path)
    parser.add_argument("--assets-manifest", required=True, type=Path)
    parser.add_argument("--uid", required=True, type=int)
    parser.add_argument("--gid", required=True, type=int)
    parser.add_argument("--chroot-base-dir", type=Path, default=Path("/srv/tinlance-jailer"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--log-dir", type=Path)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--timeout-seconds", type=float, default=45)
    parser.add_argument("--profile", choices=("W1", "W2"), default="W1")
    parser.add_argument("--w2-rootfs-tar", type=Path)
    parser.add_argument("--w2-image-id")
    parser.add_argument("--w2-base-image-digest")
    parser.add_argument("--network-namespace-path", type=Path)
    args = parser.parse_args()

    if args.runs < 1:
        parser.error("--runs must be at least 1")
    if args.uid <= 0 or args.gid <= 0:
        parser.error("a dedicated non-root uid and gid are required")
    if not args.jailer.is_file() or not args.firecracker.is_file():
        parser.error("both pinned Firecracker and jailer binaries must exist")
    if not args.firecracker_archive.is_file():
        parser.error("pinned Firecracker release archive must exist")
    if not args.chroot_base_dir.is_absolute():
        parser.error("jailer chroot base directory must be absolute")
    try:
        validate_jailer_profile_inputs(
            profile=args.profile,
            w2_rootfs_tar=args.w2_rootfs_tar,
            w2_image_id=args.w2_image_id,
            w2_base_image_digest=args.w2_base_image_digest,
            network_namespace_path=args.network_namespace_path,
        )
    except ValueError as error:
        parser.error(str(error))
    archive_sha256 = _run(
        ["sha256sum", str(args.firecracker_archive)],
        capture_output=True,
    ).stdout.split()[0]
    if archive_sha256 != FIRECRACKER_ARCHIVE_SHA256:
        raise ValueError("Firecracker release archive SHA-256 does not match the pinned release")

    manifest = load_asset_manifest(args.assets_manifest, "x86_64")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    log_dir = args.log_dir or args.output.parent / "firecracker-jailer-logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="fc-jailer-assets-", dir="/tmp") as temporary:
        work_dir = Path(temporary)
        assets = _download_pinned_guest_assets(
            work_dir,
            manifest,
            profile=args.profile,
            w2_rootfs_tar=args.w2_rootfs_tar,
        )
        kernel_path = assets["kernel_path"]
        rootfs_path = assets["rootfs_path"]
        if not isinstance(kernel_path, Path) or not isinstance(rootfs_path, Path):
            raise RuntimeError("pinned guest asset loader returned invalid paths")

        _run(["sudo", "-n", "mkdir", "-p", str(args.chroot_base_dir)])
        _run(["sudo", "-n", "chown", "root:root", str(args.chroot_base_dir)])
        _run(["sudo", "-n", "chmod", "0755", str(args.chroot_base_dir)])

        samples: list[float] = []
        guest_isolation_samples: list[dict[str, bool]] = []
        process_evidence_samples: list[dict[str, int | bool | str | list[int] | list[str]]] = []
        cgroup_evidence_samples: list[dict[str, str]] = []
        firecracker_version: dict[str, Any] = {}
        for run_index in range(1, args.runs + 1):
            jailer_id = f"fc-{os.environ.get('GITHUB_RUN_ID', 'local')}-{run_index}"
            (
                boot_time,
                process_evidence,
                cgroup_evidence,
                firecracker_version,
                guest_isolation,
            ) = _run_jailer_guest(
                jailer_binary=args.jailer,
                firecracker_binary=args.firecracker,
                jailer_id=jailer_id,
                uid=args.uid,
                gid=args.gid,
                chroot_base_dir=args.chroot_base_dir,
                kernel_path=kernel_path,
                rootfs_path=rootfs_path,
                log_path=log_dir / f"firecracker-jailer-{run_index}.log",
                timeout_seconds=args.timeout_seconds,
                profile=args.profile,
                network_namespace_path=args.network_namespace_path,
            )
            samples.append(boot_time)
            guest_isolation_samples.append(guest_isolation)
            process_evidence_samples.append(process_evidence)
            cgroup_evidence_samples.append(cgroup_evidence)

        if args.profile == "W2" and any(
            not sample.get("developer_workspace_passed", False)
            or not sample.get("host_surface_probes_passed", False)
            for sample in guest_isolation_samples
        ):
            raise PermissionError("every jailed W2 guest must prove the full developer workspace")

        report = {
            "status": "passed",
            "execution_mode": (
                "firecracker-jailer-w2-ephemeral-acceptance"
                if args.profile == "W2"
                else "firecracker-jailer-ephemeral-smoke"
            ),
            "profile": args.profile,
            "production_certification": False,
            "jailer_executed": True,
            "jailer_binary_sha256": _run(
                ["sha256sum", str(args.jailer)],
                capture_output=True,
            ).stdout.split()[0],
            "firecracker_binary_sha256": _run(
                ["sha256sum", str(args.firecracker)],
                capture_output=True,
            ).stdout.split()[0],
            "firecracker_archive_sha256": FIRECRACKER_ARCHIVE_SHA256,
            "firecracker_version": firecracker_version.get("firecracker_version"),
            "guest_asset_manifest_sha256": _run(
                ["sha256sum", str(args.assets_manifest)],
                capture_output=True,
            ).stdout.split()[0],
            "guest_kernel_sha256": assets["kernel_sha256"],
            "guest_rootfs_squashfs_sha256": assets["rootfs_squashfs_sha256"],
            "guest_rootfs_ext4_sha256": assets["rootfs_ext4_sha256"],
            "w2_base_image_digest": args.w2_base_image_digest,
            "w2_image_id": args.w2_image_id,
            "w2_rootfs_tar_sha256": assets["w2_rootfs_tar_sha256"],
            "guest_rootfs_read_only": all(
                sample["rootfs_read_only_confirmed"] for sample in guest_isolation_samples
            ),
            "guest_network_configured": False,
            "guest_isolation_checks": guest_isolation_samples,
            "boot_time_samples_ms": samples,
            **summarize_boot_times(samples),
            "process_isolation": process_evidence_samples[-1],
            "process_isolation_samples": process_evidence_samples,
            "cgroup_limits": cgroup_evidence_samples[-1],
            "cgroup_limit_samples": cgroup_evidence_samples,
        }
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
