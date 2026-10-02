"""Enterprise production acceptance and GA certification contract."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AcceptanceStatus(StrEnum):
    VERIFIED = "verified"
    NOT_VERIFIED = "not_verified"


@dataclass(frozen=True, slots=True)
class AcceptanceItem:
    control_id: str
    description: str
    status: AcceptanceStatus = AcceptanceStatus.NOT_VERIFIED
    evidence_ref: str | None = None


@dataclass(frozen=True, slots=True)
class EnterpriseAcceptance:
    release: str
    items: tuple[AcceptanceItem, ...]

    def certify(self) -> None:
        if not self.release.strip() or not self.items:
            raise ValueError("enterprise acceptance requires a release and controls")
        missing = [
            item.control_id
            for item in self.items
            if item.status is not AcceptanceStatus.VERIFIED
        ]
        if missing:
            raise RuntimeError("enterprise acceptance is incomplete: " + ", ".join(missing))
        without_evidence = [
            item.control_id
            for item in self.items
            if not item.evidence_ref or not item.evidence_ref.strip()
        ]
        if without_evidence:
            raise RuntimeError("enterprise acceptance lacks evidence: " + ", ".join(without_evidence))


def production_acceptance_items() -> tuple[AcceptanceItem, ...]:
    return (
        AcceptanceItem("identity", "Production identity provider and agent identity lifecycle"),
        AcceptanceItem("authorization", "Durable authorization and tenant isolation"),
        AcceptanceItem("execution", "R10 governed execution and hard timeout enforcement"),
        AcceptanceItem("durability", "Durable persistence, recovery and outbox publication"),
        AcceptanceItem("secrets", "External secret manager, rotation and scoped access"),
        AcceptanceItem("isolation", "Production sandbox and resource ceilings"),
        AcceptanceItem("observability", "Correlated telemetry, alerting and retention"),
        AcceptanceItem("evaluation", "Continuous adversarial and safety evaluation"),
        AcceptanceItem("supply_chain", "SBOM, vulnerability checks and signed release artifacts"),
        AcceptanceItem("recovery", "Backup restore drill, rollback and incident-response exercise"),
        AcceptanceItem("interoperability", "MCP/A2A/provider compatibility and security conformance"),
        AcceptanceItem("ownership", "Security and operational ownership assigned"),
    )
