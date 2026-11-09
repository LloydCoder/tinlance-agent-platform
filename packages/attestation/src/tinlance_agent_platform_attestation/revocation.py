"""Attestation revocation and trust lifecycle contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


def _require_aware(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")


@dataclass(frozen=True, slots=True)
class RevocationRecord:
    attestation_id: str
    reason: str
    revoked_at: datetime

    def __post_init__(self) -> None:
        if not self.attestation_id.strip() or not self.reason.strip():
            raise ValueError("revocation requires an attestation identifier and reason")
        _require_aware(self.revoked_at, "revoked_at")


@dataclass(frozen=True, slots=True)
class AttestationTrust:
    attestation_id: str
    valid_until: datetime
    revoked: bool = False
    valid_from: datetime | None = None
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.attestation_id.strip():
            raise ValueError("attestation identifier is required")
        _require_aware(self.valid_until, "valid_until")
        if self.valid_from is not None:
            _require_aware(self.valid_from, "valid_from")
            if self.valid_until <= self.valid_from:
                raise ValueError("attestation validity window must be positive")
        if self.revoked:
            if self.revoked_at is None:
                raise ValueError("revoked attestations require a revocation timestamp")
            _require_aware(self.revoked_at, "revoked_at")
        elif self.revoked_at is not None:
            raise ValueError("revocation timestamp requires revoked state")

    def usable(self, *, now: datetime | None = None) -> bool:
        current = now or datetime.now(UTC)
        _require_aware(current, "current time")
        return (
            not self.revoked
            and (self.valid_from is None or self.valid_from <= current)
            and current < self.valid_until
        )
