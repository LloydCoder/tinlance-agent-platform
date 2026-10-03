"""SRE alert, error-budget and incident-evidence contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class ErrorBudget:
    slo_target: float
    good_events: int
    total_events: int

    @property
    def allowed_failure_ratio(self) -> float:
        return 1.0 - self.slo_target

    @property
    def observed_failure_ratio(self) -> float:
        if self.total_events <= 0:
            raise ValueError("error budget requires observed events")
        return 1.0 - (self.good_events / self.total_events)

    @property
    def exhausted(self) -> bool:
        return self.observed_failure_ratio > self.allowed_failure_ratio


@dataclass(frozen=True, slots=True)
class AlertRule:
    name: str
    severity: Severity
    threshold: float

    def triggers(self, value: float) -> bool:
        return value >= self.threshold


@dataclass(frozen=True, slots=True)
class IncidentEvidence:
    incident_id: str
    severity: Severity
    summary: str
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.incident_id.strip() or not self.summary.strip():
            raise ValueError("incident evidence requires an identifier and summary")
        if not self.evidence_refs:
            raise ValueError("incident evidence requires at least one evidence reference")
        if any(not ref.strip() for ref in self.evidence_refs):
            raise ValueError("incident evidence references must be normalized")
