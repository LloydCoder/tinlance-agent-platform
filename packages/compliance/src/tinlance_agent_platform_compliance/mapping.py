"""Control, implementation, test and evidence traceability contracts."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ControlMapping:
    control_id: str
    implementation_ref: str
    test_ref: str
    evidence_ref: str
    owner: str
    framework_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        values = (self.control_id, self.implementation_ref, self.test_ref, self.evidence_ref, self.owner)
        if any(not value.strip() for value in values):
            raise ValueError("control mapping requires implementation, test, evidence and owner")
        if any(not ref.strip() for ref in self.framework_refs):
            raise ValueError("framework references must be normalized")

    def validate(self) -> None:
        if self.evidence_ref.startswith("external://"):
            return
        if not self.evidence_ref.strip():
            raise ValueError("evidence reference is required")
