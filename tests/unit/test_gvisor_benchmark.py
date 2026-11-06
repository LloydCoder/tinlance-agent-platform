from __future__ import annotations

import pytest

from scripts.benchmark_gvisor import (
    build_docker_command,
    percentile_nearest_rank,
    summarize_samples,
)


def test_percentile_nearest_rank_is_deterministic_for_three_samples() -> None:
    assert percentile_nearest_rank([10.0, 20.0, 30.0], 50) == 20.0
    assert percentile_nearest_rank([10.0, 20.0, 30.0], 95) == 30.0
    assert percentile_nearest_rank([10.0, 20.0, 30.0], 99) == 30.0


def test_percentile_rejects_invalid_samples_and_percentile() -> None:
    with pytest.raises(ValueError):
        percentile_nearest_rank([], 95)
    with pytest.raises(ValueError):
        percentile_nearest_rank([1.0], 0)
    with pytest.raises(ValueError):
        percentile_nearest_rank([1.0], 101)


def test_summary_requires_at_least_three_samples() -> None:
    with pytest.raises(ValueError, match="three"):
        summarize_samples([1.0, 2.0])


def test_summary_reports_sample_count_and_tail_latency() -> None:
    report = summarize_samples([30.0, 10.0, 20.0])
    assert report == {
        "sample_count": 3,
        "min_ms": 10.0,
        "median_ms": 20.0,
        "p95_ms": 30.0,
        "p99_ms": 30.0,
        "max_ms": 30.0,
    }


def test_docker_command_enforces_restricted_profile() -> None:
    command = build_docker_command(
        image_digest="ubuntu@sha256:" + "a" * 64,
        payload="printf tinlance-gvisor-ok",
    )
    assert command[:3] == ["docker", "run", "--rm"]
    assert "--runtime=runsc" in command
    assert "--network=none" in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--memory=512m" in command
    assert "--cpus=1" in command
    assert "--pids-limit=128" in command
    assert "ubuntu@sha256:" + "a" * 64 in command


def test_docker_command_rejects_mutable_image_reference() -> None:
    with pytest.raises(ValueError, match="digest"):
        build_docker_command(image_digest="ubuntu:24.04", payload="true")


def test_docker_command_rejects_empty_payload() -> None:
    with pytest.raises(ValueError, match="payload"):
        build_docker_command(
            image_digest="ubuntu@sha256:" + "a" * 64,
            payload="",
        )
