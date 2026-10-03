"""Independent assurance and final certification contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class FindingState(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"


@dataclass(frozen=True, slots=True)
class AssuranceFinding:
    finding_id: str
    state: FindingState
    evidence_ref: str

    def __post_init__(self) -> None:
        if not self.finding_id.strip() or not self.evidence_ref.strip():
            raise ValueError("assurance findings require identifiers and evidence")


@dataclass(frozen=True, slots=True)
class AssuranceReport:
    report_id: str
    assessor: str
    scope: tuple[str, ...]
    findings: tuple[AssuranceFinding, ...]
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.report_id.strip() or not self.assessor.strip():
            raise ValueError("assurance report requires an identifier and assessor")
        if not self.scope or not all(item.strip() for item in self.scope):
            raise ValueError("assurance report requires a non-empty scope")
        if not self.evidence_refs:
            raise ValueError("assurance report requires evidence")

    @property
    def certifiable(self) -> bool:
        return bool(self.findings) and all(
            finding.state is FindingState.RESOLVED for finding in self.findings
        )

    def certify(self) -> None:
        if not self.certifiable:
            raise RuntimeError("assurance report has unresolved findings")
