from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import signal
import subprocess
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from scripts.smoke_firecracker_guest_boot import (
    FIRECRACKER_ARCHIVE_SHA256,
    GUEST_READY_MARKER,
    _api_request,
    _download_pinned_guest_assets,
    load_asset_manifest,
    summarize_boot_times,
)

CGROUP_LIMITS = (
    ("memory.max", "805306368"),
    ("pids.max", "128"),
    ("cpu.max", "100000 100000"),
)


def build_jailer_command(
    *,
    jailer_binary: str,
    firecracker_binary: str,
    jailer_id: str,
    uid: int,
    gid: int,
    chroot_base_dir: str,
) -> list[str]:
    if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", jailer_id):
        raise ValueError("jailer identifier must be 1-64 safe alphanumeric/hyphen characters")
    if uid <= 0 or gid <= 0:
        raise ValueError("jailer must run under a non-root uid and gid")
    for path in (jailer_binary, firecracker_binary, chroot_base_dir):
        if not Path(path).is_absolute():
            raise ValueError("jailer executable and chroot paths must be absolute")

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
    for name, value in CGROUP_LIMITS:
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
    expected_chroot_root: str,
    process_root: str,
) -> dict[str, int | bool | str]:
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
    if process_root != expected_chroot_root:
        raise PermissionError(
            f"jailer process root {process_root!r} does not match expected "
            f"chroot {expected_chroot_root!r}"
        )

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
        "no_new_privs": no_new_privs,
        "capabilities_effective": capabilities_effective,
        "pid_namespace_isolated": True,
        "mount_namespace_isolated": True,
        "chroot_root": process_root,
        "cgroup_path": cgroup_v2_path,
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
                status = _parse_proc_status(
                    (entry / "status").read_text(encoding="utf-8")
                )
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
        "jailed Firecracker process could not be located by its dedicated "
        "uid and cgroup identity"
    )


def _readlink_as_root(path: Path) -> str:
    return _run(
        ["sudo", "-n", "readlink", str(path)],
        capture_output=True,
    ).stdout.strip()


def _read_process_evidence(
    pid: int,
    uid: int,
    gid: int,
    expected_chroot_root: Path,
) -> dict[str, int | bool | str]:
    proc = Path("/proc") / str(pid)
    return verify_jailer_process_evidence(
        status_text=(proc / "status").read_text(encoding="utf-8"),
        cgroup_text=(proc / "cgroup").read_text(encoding="utf-8"),
        expected_uid=uid,
        expected_gid=gid,
        host_mount_namespace=os.readlink("/proc/self/ns/mnt"),
        process_mount_namespace=_readlink_as_root(proc / "ns/mnt"),
        host_pid_namespace=os.readlink("/proc/self/ns/pid"),
        process_pid_namespace=_readlink_as_root(proc / "ns/pid"),
        expected_chroot_root=str(expected_chroot_root.resolve()),
        process_root=_readlink_as_root(proc / "root"),
    )


def _verify_cgroup_limits(cgroup_path: str) -> dict[str, str]:
    root = Path("/sys/fs/cgroup").resolve()
    candidate = (root / cgroup_path.lstrip("/")).resolve()
    if root not in candidate.parents:
        raise PermissionError("jailer cgroup escaped the cgroup v2 mount")
    expected = {
        "memory.max": "805306368",
        "pids.max": "128",
        "cpu.max": "100000 100000",
    }
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
) -> tuple[float, dict[str, int | bool | str], dict[str, str], dict[str, str]]:
    command = build_jailer_command(
        jailer_binary=str(jailer_binary),
        firecracker_binary=str(firecracker_binary),
        jailer_id=jailer_id,
        uid=uid,
        gid=gid,
        chroot_base_dir=str(chroot_base_dir),
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
            process_cgroup = (
                Path("/proc") / str(firecracker_pid) / "cgroup"
            ).read_text(encoding="utf-8")
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
                {"vcpu_count": 1, "mem_size_mib": 512, "smt": False},
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
                if GUEST_READY_MARKER in log_text:
                    process_evidence = _read_process_evidence(
                        firecracker_pid,
                        uid,
                        gid,
                        chroot_root,
                    )
                    cgroup_evidence = _verify_cgroup_limits(cgroup_path)
                    return (
                        (time.monotonic() - started) * 1000,
                        process_evidence,
                        cgroup_evidence,
                        version,
                    )
                if not _is_process_alive(firecracker_pid):
                    raise RuntimeError(
                        "jailed Firecracker exited before guest readiness: "
                        f"{log_text[-5000:]}"
                    )
                time.sleep(0.1)
            log_text = log_path.read_text(encoding="utf-8", errors="replace")
            raise TimeoutError(f"jailed guest did not reach readiness: {log_text[-5000:]}")
    finally:
        if process is not None:
            _stop_process(process, firecracker_pid)
        if cgroup_path is not None:
            cgroup_dir = Path("/sys/fs/cgroup") / cgroup_path.lstrip("/")
            subprocess.run(
                ["sudo", "-n", "rmdir", "--", str(cgroup_dir)],
                check=False,
                capture_output=True,
                text=True,
            )
        subprocess.run(
            ["sudo", "-n", "rm", "-rf", "--", str(chroot_base_dir / "firecracker" / jailer_id)],
            check=False,
            capture_output=True,
            text=True,
        )


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
        assets = _download_pinned_guest_assets(work_dir, manifest)
        kernel_path = assets["kernel_path"]
        rootfs_path = assets["rootfs_path"]
        if not isinstance(kernel_path, Path) or not isinstance(rootfs_path, Path):
            raise RuntimeError("pinned guest asset loader returned invalid paths")

        _run(["sudo", "-n", "mkdir", "-p", str(args.chroot_base_dir)])
        _run(["sudo", "-n", "chown", "root:root", str(args.chroot_base_dir)])
        _run(["sudo", "-n", "chmod", "0755", str(args.chroot_base_dir)])

        samples: list[float] = []
        process_evidence: dict[str, int | bool | str] = {}
        cgroup_evidence: dict[str, str] = {}
        firecracker_version: dict[str, Any] = {}
        for run_index in range(1, args.runs + 1):
            jailer_id = f"fc-{os.environ.get('GITHUB_RUN_ID', 'local')}-{run_index}"
            boot_time, process_evidence, cgroup_evidence, firecracker_version = _run_jailer_guest(
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
            )
            samples.append(boot_time)

        report = {
            "status": "passed",
            "execution_mode": "firecracker-jailer-ephemeral-smoke",
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
            "boot_time_samples_ms": samples,
            **summarize_boot_times(samples),
            "process_isolation": process_evidence,
            "cgroup_limits": cgroup_evidence,
        }
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
