"""Recovery objectives and chaos-drill contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class FailureMode(StrEnum):
    WORKER_CRASH = "worker_crash"
    DATABASE_OUTAGE = "database_outage"
    QUEUE_OUTAGE = "queue_outage"
    NETWORK_PARTITION = "network_partition"
    DUPLICATE_DELIVERY = "duplicate_delivery"
    PROVIDER_TIMEOUT = "provider_timeout"
    REGIONAL_FAILURE = "regional_failure"


@dataclass(frozen=True, slots=True)
class RecoveryObjective:
    rto_seconds: int
    rpo_seconds: int

    def __post_init__(self) -> None:
        if self.rto_seconds < 0 or self.rpo_seconds < 0:
            raise ValueError("recovery objectives cannot be negative")


@dataclass(frozen=True, slots=True)
class RecoveryDrill:
    drill_id: str
    failure_mode: FailureMode
    objective: RecoveryObjective
    observed_rto_seconds: int
    observed_rpo_seconds: int
    evidence_ref: str

    def __post_init__(self) -> None:
        if not self.drill_id.strip() or not self.evidence_ref.strip():
            raise ValueError("recovery drills require an identifier and evidence")
        if self.observed_rto_seconds < 0 or self.observed_rpo_seconds < 0:
            raise ValueError("observed recovery values cannot be negative")

    @property
    def passed(self) -> bool:
        return (
            self.observed_rto_seconds <= self.objective.rto_seconds
            and self.observed_rpo_seconds <= self.objective.rpo_seconds
        )


@dataclass(frozen=True, slots=True)
class RecoveryGate:
    drills: tuple[RecoveryDrill, ...]

    def evaluate(self) -> None:
        if not self.drills:
            raise ValueError("recovery gate requires drills")
        failures = [drill.drill_id for drill in self.drills if not drill.passed]
        if failures:
            raise RuntimeError("recovery gate failed: " + ", ".join(failures))
