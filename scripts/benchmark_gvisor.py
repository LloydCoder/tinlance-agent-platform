from __future__ import annotations

import argparse
import json
import math
import platform
import re
import statistics
import subprocess
import time
from pathlib import Path
from typing import Any

_IMAGE_DIGEST = re.compile(r"^[A-Za-z0-9./:_-]+@sha256:[a-f0-9]{64}$")
_RUNTIME_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_SUCCESS_MARKER = "TINLANCE_GVISOR_WORKLOAD_OK"


def percentile_nearest_rank(samples: list[float], percentile: int) -> float:
    if not samples:
        raise ValueError("at least one sample is required")
    if not 1 <= percentile <= 100:
        raise ValueError("percentile must be between 1 and 100")
    ordered = sorted(float(value) for value in samples)
    if any(value < 0 for value in ordered):
        raise ValueError("latency samples cannot be negative")
    rank = max(1, math.ceil(percentile / 100 * len(ordered)))
    return ordered[rank - 1]


def summarize_samples(samples: list[float]) -> dict[str, int | float]:
    if len(samples) < 3:
        raise ValueError("at least three samples are required for a benchmark summary")
    values = sorted(float(value) for value in samples)
    if any(value < 0 for value in values):
        raise ValueError("latency samples cannot be negative")
    return {
        "sample_count": len(values),
        "min_ms": values[0],
        "median_ms": statistics.median(values),
        "p95_ms": percentile_nearest_rank(values, 95),
        "p99_ms": percentile_nearest_rank(values, 99),
        "max_ms": values[-1],
    }


def build_docker_command(*, image_digest: str, payload: str) -> list[str]:
    if not _IMAGE_DIGEST.fullmatch(image_digest):
        raise ValueError("image reference must be pinned by sha256 digest")
    if not isinstance(payload, str) or not payload.strip() or "\x00" in payload:
        raise ValueError("payload must be non-empty text without NUL bytes")
    return [
        "docker",
        "run",
        "--rm",
        "--runtime=runsc",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--cpus=1",
        "--memory=512m",
        "--pids-limit=128",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--workdir=/tmp",
        image_digest,
        "sh",
        "-lc",
        payload,
    ]


def _capture(command: list[str]) -> str:
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
    return result.stdout.strip()


def run_benchmark(
    *,
    image_digest: str,
    runs: int = 30,
    runtime_name: str = "runsc",
    runtime_version: str | None = None,
    candidate: str | None = None,
) -> dict[str, Any]:
    if runs < 3 or runs > 100:
        raise ValueError("runs must be between 3 and 100")
    if not _RUNTIME_NAME.fullmatch(runtime_name):
        raise ValueError("runtime name must be a safe Docker runtime identifier")
    version = runtime_version or _capture([runtime_name, "--version"])
    docker_server = _capture(["docker", "version", "--format", "{{.Server.Version}}"])
    runtime_inventory = _capture(["docker", "info", "--format", "{{json .Runtimes}}"])
    runtimes = json.loads(runtime_inventory)
    if runtime_name not in runtimes:
        raise RuntimeError(f"Docker does not report the {runtime_name} runtime")
    payload = (
        "set -eu; "
        "if touch /etc/tinlance-readonly-probe 2>/dev/null; then "
        "echo TINLANCE_ROOTFS_WRITE_UNEXPECTED; exit 71; fi; "
        "echo TINLANCE_ROOTFS_READ_ONLY_CONFIRMED; "
        "if awk 'NR>2 && $1 !~ /^lo:/ { found=1 } END { exit found }' /proc/net/dev; "
        "then echo TINLANCE_NO_NIC_CONFIRMED; else "
        "echo TINLANCE_NETWORK_INTERFACE_UNEXPECTED; exit 72; fi; "
        "printf tinlance-gvisor-ok > /tmp/workload.txt; "
        'test "$(cat /tmp/workload.txt)" = tinlance-gvisor-ok; '
        f"echo {_SUCCESS_MARKER}"
    )
    command = build_docker_command(
        image_digest=image_digest,
        payload=payload,
        runtime_name=runtime_name,
    )
    samples: list[float] = []
    outputs: list[str] = []
    for _ in range(runs):
        started = time.perf_counter()
        output = _capture(command)
        elapsed_ms = (time.perf_counter() - started) * 1000
        if _SUCCESS_MARKER not in output:
            raise RuntimeError("gVisor workload did not emit its success marker")
        if "TINLANCE_ROOTFS_READ_ONLY_CONFIRMED" not in output:
            raise RuntimeError("gVisor workload did not confirm a read-only root filesystem")
        if "TINLANCE_NO_NIC_CONFIRMED" not in output:
            raise RuntimeError("gVisor workload did not confirm a network-disconnected namespace")
        samples.append(elapsed_ms)
        outputs.append(output)
    return {
        "schema_version": "tinlance-sandbox-benchmark.v1",
        "candidate": candidate or ("gvisor-runsc" if runtime_name == "runsc" else runtime_name),
        "runtime_name": runtime_name,
        "runtime_version": version,
        "docker_server_version": docker_server,
        "host_kernel": platform.release(),
        "host_architecture": platform.machine(),
        "image_digest": image_digest,
        "workload": {
            "profile": "W1-minimal-agent",
            "network": "none",
            "read_only_rootfs": True,
            "capabilities": "drop-all",
            "no_new_privileges": True,
            "cpu_limit": "1",
            "memory_limit": "512m",
            "pids_limit": 128,
            "tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=64m",
        },
        "latency": {**summarize_samples(samples), "samples_ms": samples},
        "guest_assertions": {
            "rootfs_read_only": True,
            "network_has_only_loopback": True,
            "filesystem_write_in_tmpfs": True,
        },
        "outputs": outputs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Tinlance gVisor W1 benchmark.")
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--runtime-name", default="runsc")
    parser.add_argument("--runtime-version")
    parser.add_argument("--candidate")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_benchmark(
        image_digest=args.image_digest,
        runs=args.runs,
        runtime_name=args.runtime_name,
        runtime_version=args.runtime_version,
        candidate=args.candidate,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    latency = report["latency"]
    print(
        f"gVisor {report['runtime_version']}: {latency['sample_count']} W1 runs; "
        f"median={latency['median_ms']:.1f} ms; p95={latency['p95_ms']:.1f} ms"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
