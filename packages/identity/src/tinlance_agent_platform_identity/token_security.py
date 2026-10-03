"""Token validation and sender-constraint metadata contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class TokenSecurityContext:
    issuer: str
    audience: tuple[str, ...]
    subject: str
    token_id: str
    issued_at: datetime
    expires_at: datetime
    nonce: str | None = None
    sender_key_thumbprint: str | None = None

    def validate(
        self,
        *,
        expected_issuer: str,
        expected_audience: str,
        now: datetime | None = None,
        expected_nonce: str | None = None,
    ) -> None:
        current = now or datetime.now(UTC)
        if self.issuer != expected_issuer:
            raise PermissionError("token issuer is not trusted")
        if expected_audience not in self.audience:
            raise PermissionError("token audience is not trusted")
        if not self.subject.strip() or not self.token_id.strip():
            raise PermissionError("token subject and identifier are required")
        if self.expires_at <= current or self.issued_at > current:
            raise PermissionError("token is outside its validity window")
        if expected_nonce is not None and self.nonce != expected_nonce:
            raise PermissionError("token nonce does not match the request")
        if self.sender_key_thumbprint is not None and not self.sender_key_thumbprint.strip():
            raise PermissionError("sender constraint cannot be empty")
