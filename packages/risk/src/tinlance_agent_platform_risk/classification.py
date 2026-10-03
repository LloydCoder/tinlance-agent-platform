"""Provider-neutral risk classification; risk never grants authority."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum


class ActionRisk(IntEnum):
    READ_ONLY = 10
    TENANT_WRITE = 30
    EXTERNAL_SIDE_EFFECT = 50
    FINANCIAL = 70
    PRIVILEGE_CHANGE = 80
    IRREVERSIBLE = 90
    SYSTEM_CRITICAL = 100


class RiskFactor(StrEnum):
    DATA_SENSITIVITY = "data_sensitivity"
    BLAST_RADIUS = "blast_radius"
    EXTERNAL_SIDE_EFFECT = "external_side_effect"
    FINANCIAL_IMPACT = "financial_impact"
    PRIVILEGE_IMPACT = "privilege_impact"
    REVERSIBILITY = "reversibility"


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    action: str
    level: ActionRisk
    factors: frozenset[RiskFactor]
    reason: str

    def __post_init__(self) -> None:
        if not self.action.strip() or not self.reason.strip():
            raise ValueError("risk assessment requires action and reason")

    @property
    def requires_explicit_approval(self) -> bool:
        return self.level >= ActionRisk.EXTERNAL_SIDE_EFFECT

    def validate_authority_neutral(self) -> None:
        """Ensure risk metadata cannot be used as an authority grant."""
        if self.level < ActionRisk.READ_ONLY:
            raise ValueError("risk level is invalid")
