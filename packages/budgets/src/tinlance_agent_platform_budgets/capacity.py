"""Capacity and economic governance contracts."""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CapacityEnvelope:
    minimum_throughput_per_minute: float
    maximum_p95_ms: float
    maximum_p99_ms: float
    maximum_concurrency: int

    def __post_init__(self) -> None:
        if (
            not all(
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and math.isfinite(value)
                for value in (
                    self.minimum_throughput_per_minute,
                    self.maximum_p95_ms,
                    self.maximum_p99_ms,
                )
            )
            or any(value < 0 for value in (
                self.minimum_throughput_per_minute,
                self.maximum_p95_ms,
                self.maximum_p99_ms,
            ))
            or isinstance(self.maximum_concurrency, bool)
            or not isinstance(self.maximum_concurrency, int)
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
            not all(
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and math.isfinite(value)
                for value in (self.throughput_per_minute, self.p95_ms, self.p99_ms)
            )
            or any(value < 0 for value in (
                self.throughput_per_minute, self.p95_ms, self.p99_ms, self.concurrency
            ))
            or isinstance(self.concurrency, bool)
            or not isinstance(self.concurrency, int)
            or self.p95_ms > self.p99_ms
        ):
            raise ValueError("capacity observation values are invalid")

@dataclass(frozen=True, slots=True)
class CapacityGate:
    envelope: CapacityEnvelope
    observation: CapacityObservation
    evidence_ref: str

    def __post_init__(self) -> None:
        if not self.evidence_ref.strip():
            raise ValueError("capacity evidence is required")

    @property
    def within(self) -> bool:
        return (
            self.observation.throughput_per_minute >= self.envelope.minimum_throughput_per_minute
            and self.observation.p95_ms <= self.envelope.maximum_p95_ms
            and self.observation.p99_ms <= self.envelope.maximum_p99_ms
            and self.observation.concurrency <= self.envelope.maximum_concurrency
        )

    def evaluate(self) -> None:
        if not self.within:
            raise RuntimeError("capacity envelope was exceeded")


@dataclass(frozen=True, slots=True)
class TenantQuota:
    max_concurrency: int
    max_tool_calls: int
    max_token_units: int
    max_cost_units: float

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_concurrency, bool)
            or not isinstance(self.max_concurrency, int)
            or isinstance(self.max_tool_calls, bool)
            or not isinstance(self.max_tool_calls, int)
            or isinstance(self.max_token_units, bool)
            or not isinstance(self.max_token_units, int)
            or isinstance(self.max_cost_units, bool)
            or not isinstance(self.max_cost_units, (int, float))
            or not math.isfinite(self.max_cost_units)
            or self.max_concurrency < 1
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
        if (
            any(isinstance(value, bool) or not isinstance(value, int)
                for value in (concurrency, tool_calls, token_units))
            or isinstance(cost_units, bool)
            or not isinstance(cost_units, (int, float))
            or not math.isfinite(cost_units)
            or concurrency < 0 or tool_calls < 0 or token_units < 0 or cost_units < 0
        ):
            return False
        return (
            concurrency <= self.max_concurrency
            and tool_calls <= self.max_tool_calls
            and token_units <= self.max_token_units
            and cost_units <= self.max_cost_units
        )
