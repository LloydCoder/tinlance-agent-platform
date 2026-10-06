"""Capacity and economic governance contracts."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CapacityEnvelope:
    minimum_throughput_per_minute: float
    maximum_p95_ms: float
    maximum_p99_ms: float
    maximum_concurrency: int

    def __post_init__(self) -> None:
        if (
            self.minimum_throughput_per_minute < 0
            or self.maximum_p95_ms < 0
            or self.maximum_p99_ms < 0
            or self.maximum_concurrency < 1
        ):
            raise ValueError("capacity envelope values are invalid")
        if self.maximum_p95_ms > self.maximum_p99_ms:
            raise ValueError("p95 latency ceiling cannot exceed p99 latency ceiling")


@dataclass(frozen=True, slots=True)
class CapacityObservation:
    throughput_per_minute: float
    p95_ms: float
    p99_ms: float
    concurrency: int

    def __post_init__(self) -> None:
        if (
            self.throughput_per_minute < 0
            or self.p95_ms < 0
            or self.p99_ms < 0
            or self.concurrency < 0
            or self.p95_ms > self.p99_ms
        ):
            raise ValueError("capacity observation values are invalid")

    @property
    def within(self) -> bool:
        return True


@dataclass(frozen=True, slots=True)
class CapacityGate:
    envelope: CapacityEnvelope
    observation: CapacityObservation
    evidence_ref: str

    def __post_init__(self) -> None:
        if not self.evidence_ref.strip():
            raise ValueError("capacity evidence is required")

    def evaluate(self) -> None:
        if self.observation.throughput_per_minute < self.envelope.minimum_throughput_per_minute:
            raise RuntimeError("capacity throughput target failed")
        if self.observation.p95_ms > self.envelope.maximum_p95_ms:
            raise RuntimeError("capacity p95 target failed")
        if self.observation.p99_ms > self.envelope.maximum_p99_ms:
            raise RuntimeError("capacity p99 target failed")
        if self.observation.concurrency > self.envelope.maximum_concurrency:
            raise RuntimeError("capacity concurrency target failed")


@dataclass(frozen=True, slots=True)
class TenantQuota:
    max_concurrency: int
    max_tool_calls: int
    max_token_units: int
    max_cost_units: float

    def __post_init__(self) -> None:
        if (
            self.max_concurrency < 1
            or self.max_tool_calls < 0
            or self.max_token_units < 0
            or self.max_cost_units < 0
        ):
            raise ValueError("tenant quota values are invalid")

    def admits(
        self,
        *,
        concurrency: int,
        tool_calls: int,
        token_units: int,
        cost_units: float,
    ) -> bool:
        if concurrency < 0 or tool_calls < 0 or token_units < 0 or cost_units < 0:
            return False
        return (
            concurrency <= self.max_concurrency
            and tool_calls <= self.max_tool_calls
            and token_units <= self.max_token_units
            and cost_units <= self.max_cost_units
        )
