"""Capacity, admission and economic governance contracts."""

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


@dataclass(frozen=True, slots=True)
class CapacityObservation:
    throughput_per_minute: float
    p95_ms: float
    p99_ms: float
    concurrency: int

    @property
    def within(self) -> bool:
        return self.throughput_per_minute >= 0 and self.p95_ms >= 0 and self.p99_ms >= 0


@dataclass(frozen=True, slots=True)
class CapacityGate:
    envelope: CapacityEnvelope
    observation: CapacityObservation
    evidence_ref: str

    def __post_init__(self) -> None:
        if not self.evidence_ref.strip():
            raise ValueError("capacity evidence is required")

    def evaluate(self) -> None:
        if not self.observation.within:
            raise RuntimeError("capacity observation is invalid")
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

    def admits(
        self,
        *,
        concurrency: int,
        tool_calls: int,
        token_units: int,
        cost_units: float,
    ) -> bool:
        return (
            concurrency <= self.max_concurrency
            and tool_calls <= self.max_tool_calls
            and token_units <= self.max_token_units
            and cost_units <= self.max_cost_units
        )
