"""Release provenance, compatibility and rollback contracts."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ReleaseManifest:
    version: str
    source_revision: str
    artifact_digest: str
    sbom_ref: str
    provenance_ref: str
    signature_ref: str

    def __post_init__(self) -> None:
        values = (
            self.version,
            self.source_revision,
            self.artifact_digest,
            self.sbom_ref,
            self.provenance_ref,
            self.signature_ref,
        )
        if any(not value.strip() for value in values):
            raise ValueError("release manifest requires complete provenance")
        if not self.artifact_digest.startswith(("sha256:", "sha384:", "sha512:")):
            raise ValueError("release artifact digest must be algorithm-qualified")


@dataclass(frozen=True, slots=True)
class UpgradePlan:
    migration_id: str
    backward_compatible: bool
    rollback_ref: str

    def __post_init__(self) -> None:
        if not self.migration_id.strip() or not self.rollback_ref.strip():
            raise ValueError("upgrade plan requires migration and rollback references")


@dataclass(frozen=True, slots=True)
class ReleaseGate:
    manifest: ReleaseManifest
    upgrade: UpgradePlan

    def evaluate(self) -> None:
        if not self.upgrade.backward_compatible and not self.upgrade.rollback_ref.strip():
            raise RuntimeError("non-compatible releases require rollback evidence")
