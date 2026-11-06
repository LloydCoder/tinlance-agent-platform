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
import tempfile
import time
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypedDict, cast
from urllib.parse import urlencode

S3_BASE = "https://s3.amazonaws.com/spec.ccfc.min"
FIRECRACKER_VERSION = "1.17.0"
GUEST_READY_MARKER = "TINLANCE_GUEST_READY"
FIRECRACKER_ARCHIVE_SHA256 = "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558"


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
    return {
        "sample_count": len(values),
        "median_boot_time_ms": statistics.median(values),
        "max_boot_time_ms": max(values),
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


def _prepare_rootfs(squashfs_path: Path, rootfs_path: Path, extract_dir: Path) -> None:
    _run(["unsquashfs", "-d", str(extract_dir), str(squashfs_path)])
    init_path = extract_dir / "usr/local/sbin/tinlance-guest-init"
    init_path.parent.mkdir(parents=True, exist_ok=True)
    init_path.write_text(
        "#!/bin/sh\necho TINLANCE_GUEST_READY\nexec /usr/bin/sleep 60\n",
        encoding="utf-8",
    )
    init_path.chmod(0o755)
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
    _run(["sudo", "-n", "chown", "-R", "root:root", str(extract_dir)])
    try:
        _run(["truncate", "-s", "1G", str(rootfs_path)])
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
) -> tuple[float, dict[str, str]]:
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
                {"vcpu_count": 1, "mem_size_mib": 512, "smt": False},
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
                if GUEST_READY_MARKER in log_text:
                    return (time.monotonic() - started) * 1000, version
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
) -> dict[str, object]:
    kernel_path = work_dir / "guest-vmlinux"
    squashfs_path = work_dir / "guest-rootfs.squashfs"
    rootfs_path = work_dir / "guest-rootfs.ext4"
    _download(f"{S3_BASE}/{manifest['kernel_key']}", kernel_path)
    _download(f"{S3_BASE}/{manifest['rootfs_key']}", squashfs_path)
    kernel_sha256 = _sha256(kernel_path)
    rootfs_squashfs_sha256 = _sha256(squashfs_path)
    if kernel_sha256 != manifest["kernel_sha256"]:
        raise ValueError("downloaded guest kernel SHA-256 does not match the pinned manifest")
    if rootfs_squashfs_sha256 != manifest["rootfs_squashfs_sha256"]:
        raise ValueError("downloaded guest rootfs SHA-256 does not match the pinned manifest")
    _prepare_rootfs(squashfs_path, rootfs_path, work_dir / "squashfs-root")
    return {
        **manifest,
        "kernel_path": kernel_path,
        "squashfs_path": squashfs_path,
        "rootfs_path": rootfs_path,
        "kernel_sha256": kernel_sha256,
        "rootfs_squashfs_sha256": rootfs_squashfs_sha256,
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
            Path(__file__).resolve().parents[1]
            / "tests/fixtures/firecracker-guest-assets.json"
        ),
    )
    parser.add_argument("--discover-latest", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--log-dir", type=Path)
    parser.add_argument("--runs", type=int, default=3)
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
        assets = _download_pinned_guest_assets(work_dir, manifest)
        kernel_path = assets["kernel_path"]
        rootfs_path = assets["rootfs_path"]
        if not isinstance(kernel_path, Path) or not isinstance(rootfs_path, Path):
            raise RuntimeError("pinned guest asset loader returned invalid paths")

        samples: list[float] = []
        firecracker_version: dict[str, str] = {}
        for run_index in range(1, args.runs + 1):
            boot_time_ms, version = _run_guest(
                firecracker_binary,
                kernel_path,
                rootfs_path,
                run_index,
                work_dir,
                log_dir,
                args.timeout_seconds,
            )
            samples.append(boot_time_ms)
            firecracker_version = version

        summary = summarize_boot_times(samples)
        report = {
            "status": "passed",
            "execution_mode": "direct-vmm-ephemeral-smoke",
            "jailer_executed": False,
            "production_certification": False,
            "guest_network_configured": False,
            "guest_rootfs_read_only": True,
            "guest_ready_marker": GUEST_READY_MARKER,
            "boot_time_measurement": (
                "elapsed time from immediately before the InstanceStart API request "
                "until the guest init marker appears on the serial console"
            ),
            "firecracker_version": firecracker_version.get("firecracker_version"),
            "firecracker_archive_sha256": archive_sha256,
            "guest_asset_manifest_sha256": _sha256(args.assets_manifest),
            "guest_architecture": platform.machine(),
            "host_kernel_release": platform.release(),
            "upstream_ci_artifact_prefix": assets["artifact_prefix"],
            "guest_kernel_key": assets["kernel_key"],
            "guest_rootfs_key": assets["rootfs_key"],
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
