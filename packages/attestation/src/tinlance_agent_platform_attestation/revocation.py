"""Attestation revocation and trust lifecycle contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class RevocationRecord:
    attestation_id: str
    reason: str
    revoked_at: datetime

    def __post_init__(self) -> None:
        if not self.attestation_id.strip() or not self.reason.strip():
            raise ValueError("revocation requires an attestation identifier and reason")


@dataclass(frozen=True, slots=True)
class AttestationTrust:
    attestation_id: str
    valid_until: datetime
    revoked: bool = False

    def usable(self, *, now: datetime | None = None) -> bool:
        current = now or datetime.now(UTC)
        return not self.revoked and current < self.valid_until
