"""Lifecycle, compatibility and provenance contracts for governed resources."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class LifecycleAction(StrEnum):
    ACTIVATE = "activate"
    DEPRECATE = "deprecate"
    REVOKE = "revoke"


@dataclass(frozen=True, slots=True)
class Compatibility:
    protocol: str
    minimum_version: str
    maximum_version: str | None = None

    def supports(self, version: str) -> bool:
        if not version.strip():
            raise ValueError("version is required")
        if version < self.minimum_version:
            return False
        if self.maximum_version is not None and version > self.maximum_version:
            return False
        return True


@dataclass(frozen=True, slots=True)
class ResourceGovernance:
    resource_name: str
    version: str
    digest: str
    provenance_ref: str
    compatibility: tuple[Compatibility, ...] = ()
    revoked: bool = False

    def __post_init__(self) -> None:
        values = (self.resource_name, self.version, self.digest, self.provenance_ref)
        if any(not value.strip() for value in values):
            raise ValueError("resource governance fields are required")
        if not self.digest.startswith(("sha256:", "sha384:", "sha512:")):
            raise ValueError("resource digest must be algorithm-qualified")

    def assert_usable(self, protocol: str, version: str) -> None:
        if self.revoked:
            raise PermissionError("resource is revoked")
        matches = [item for item in self.compatibility if item.protocol == protocol]
        if not matches or not any(item.supports(version) for item in matches):
            raise RuntimeError("resource is incompatible with the requested protocol version")
