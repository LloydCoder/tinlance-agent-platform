"""Reliability and correlation contracts for production observability."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class CorrelationContext:
    tenant_id: str
    run_id: UUID
    execution_id: UUID | None = None
    trace_id: str | None = None
    parent_span_id: str | None = None

    def validate(self) -> None:
        if not self.tenant_id or self.tenant_id != self.tenant_id.strip():
            raise ValueError("tenant scope is required")
        if self.trace_id is not None and not self.trace_id.strip():
            raise ValueError("trace_id cannot be empty")
        if self.parent_span_id is not None and not self.parent_span_id.strip():
            raise ValueError("parent_span_id cannot be empty")


@dataclass(frozen=True, slots=True)
class SLO:
    name: str
    target: float
    window_seconds: int

    def __post_init__(self) -> None:
        if not self.name.strip() or not 0.0 <= self.target <= 1.0 or self.window_seconds <= 0:
            raise ValueError("invalid SLO")


@dataclass(frozen=True, slots=True)
class SLOMeasurement:
    slo: SLO
    good_events: int
    total_events: int

    @property
    def ratio(self) -> float:
        if self.total_events < 0 or self.good_events < 0 or self.good_events > self.total_events:
            raise ValueError("invalid SLO measurement")
        return self.good_events / self.total_events if self.total_events else 1.0

    @property
    def met(self) -> bool:
        return self.ratio >= self.slo.target
