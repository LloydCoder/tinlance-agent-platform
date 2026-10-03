"""Provider-neutral attestation claims; verification remains authoritative."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum


class AttestationType(StrEnum):
    AGENT = "agent"
    WORKLOAD = "workload"
    ARTIFACT = "artifact"
    RUNTIME = "runtime"


@dataclass(frozen=True, slots=True)
class Attestation:
    subject: str
    attestation_type: AttestationType
    issuer: str
    artifact_digest: str
    issued_at: datetime
    expires_at: datetime
    nonce: str

    def validate(self, *, now: datetime | None = None) -> None:
        current = now or datetime.now(UTC)
        values = (self.subject, self.issuer, self.artifact_digest, self.nonce)
        if any(not value.strip() for value in values):
            raise ValueError("attestation identity fields are required")
        if self.expires_at <= current or self.issued_at > current:
            raise PermissionError("attestation is outside its validity window")
        if not self.artifact_digest.startswith(("sha256:", "sha384:", "sha512:")):
            raise ValueError("attestation artifact digest must be algorithm-qualified")
