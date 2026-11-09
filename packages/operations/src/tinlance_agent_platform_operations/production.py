"""Production dependency readiness contracts.

These contracts record operator evidence; they do not pretend that repository CI
has deployed external production infrastructure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from urllib.parse import urlsplit

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_ENVIRONMENT_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_EVIDENCE_SCHEMES = frozenset({"evidence", "https", "s3"})


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
    verified_by: str | None = None
    verified_at: datetime | None = None
    expires_at: datetime | None = None
    evidence_sha256: str | None = None
    environment: str = "production"

    def __post_init__(self) -> None:
        if not self.name or self.name != self.name.strip():
            raise ValueError("production dependency name is required and must be trimmed")
        if not _ENVIRONMENT_PATTERN.fullmatch(self.environment):
            raise ValueError("production dependency environment must be a normalized identifier")
        if not isinstance(self.verified, bool):
            raise ValueError("production dependency verified flag must be boolean")

        for label, timestamp in (
            ("verification", self.verified_at),
            ("evidence expiry", self.expires_at),
        ):
            if timestamp is not None and (
                timestamp.tzinfo is None or timestamp.utcoffset() is None
            ):
                raise ValueError(f"{label} timestamp must be timezone-aware")

        if self.evidence_sha256 is not None and not _SHA256_PATTERN.fullmatch(self.evidence_sha256):
            raise ValueError("evidence digest must be a lowercase SHA-256 hex value")

        if (
            self.expires_at is not None
            and self.verified_at is not None
            and self.expires_at <= self.verified_at
        ):
            raise ValueError("evidence expiry must be later than verification time")

        if self.verified:
            if not self.evidence_ref:
                raise ValueError("verified production dependencies require evidence")
            parsed = urlsplit(self.evidence_ref)
            if parsed.scheme not in _EVIDENCE_SCHEMES:
                raise ValueError("verified dependency evidence must use an approved URI scheme")
            if not parsed.netloc:
                raise ValueError("verified dependency evidence URI must identify a resource")
            if not self.verified_by or not self.verified_by.strip():
                raise ValueError("verified production dependencies require a named verifier")
            if self.verified_at is None:
                raise ValueError(
                    "verified production dependencies require a verification timestamp"
                )
            if self.evidence_sha256 is None:
                raise ValueError(
                    "verified production dependencies require a SHA-256 evidence digest"
                )


@dataclass(frozen=True, slots=True)
class ProductionReadiness:
    release: str
    dependencies: tuple[ProductionDependency, ...]
    environment: str = "production"

    def verify(self, *, now: datetime | None = None) -> None:
        if not self.release or self.release != self.release.strip() or not self.dependencies:
            raise ValueError("production readiness requires a release and dependencies")
        if not _ENVIRONMENT_PATTERN.fullmatch(self.environment):
            raise ValueError("production readiness environment must be a normalized identifier")

        verification_time = now or datetime.now(UTC)
        if verification_time.tzinfo is None or verification_time.utcoffset() is None:
            raise ValueError("readiness verification time must be timezone-aware")

        kinds = [dependency.kind for dependency in self.dependencies]
        if len(kinds) != len(set(kinds)):
            raise ValueError("production readiness contains duplicate dependency kinds")

        required = set(DependencyKind)
        present = set(kinds)
        missing = required - present
        if missing:
            names = ", ".join(sorted(kind.value for kind in missing))
            raise RuntimeError("production readiness is missing dependencies: " + names)

        unverified = [
            dependency.kind.value for dependency in self.dependencies if not dependency.verified
        ]
        if unverified:
            raise RuntimeError(
                "production readiness has unverified dependencies: " + ", ".join(unverified)
            )

        mismatched = [
            dependency.kind.value
            for dependency in self.dependencies
            if dependency.environment != self.environment
        ]
        if mismatched:
            raise RuntimeError(
                "production readiness evidence environment mismatch: " + ", ".join(mismatched)
            )

        future_dated = [
            dependency.kind.value
            for dependency in self.dependencies
            if dependency.verified_at is not None and dependency.verified_at > verification_time
        ]
        if future_dated:
            raise RuntimeError(
                "production readiness contains future-dated evidence: " + ", ".join(future_dated)
            )

        expired = [
            dependency.kind.value
            for dependency in self.dependencies
            if dependency.expires_at is not None and dependency.expires_at <= verification_time
        ]
        if expired:
            raise RuntimeError(
                "production readiness contains expired evidence: " + ", ".join(expired)
            )
