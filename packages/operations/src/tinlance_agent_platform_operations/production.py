"""Production dependency readiness contracts.

These contracts record operator evidence; they do not pretend that repository CI
has deployed external production infrastructure.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class DependencyKind(StrEnum):
    DATABASE = "database"
    OUTBOX = "outbox"
    SECRET_MANAGER = "secret_manager"
    SANDBOX = "sandbox"
    TELEMETRY = "telemetry"
    BACKUP = "backup"
    INCIDENT_RESPONSE = "incident_response"
    OWNERSHIP = "ownership"


@dataclass(frozen=True, slots=True)
class ProductionDependency:
    kind: DependencyKind
    name: str
    verified: bool
    evidence_ref: str | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("production dependency name is required")
        if self.verified and not self.evidence_ref:
            raise ValueError("verified production dependencies require evidence")


@dataclass(frozen=True, slots=True)
class ProductionReadiness:
    release: str
    dependencies: tuple[ProductionDependency, ...]

    def verify(self) -> None:
        if not self.release.strip() or not self.dependencies:
            raise ValueError("production readiness requires a release and dependencies")
        required = set(DependencyKind)
        present = {dependency.kind for dependency in self.dependencies}
        missing = required - present
        if missing:
            names = ", ".join(sorted(kind.value for kind in missing))
            raise RuntimeError("production readiness is missing dependencies: " + names)
        unverified = [
            dependency.kind.value
            for dependency in self.dependencies
            if not dependency.verified
        ]
        if unverified:
            raise RuntimeError(
                "production readiness has unverified dependencies: " + ", ".join(unverified)
            )
