"""Token validation and sender-constraint metadata contracts."""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass
from datetime import UTC, datetime


def _require_aware(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")


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
    not_before: datetime | None = None

    def __post_init__(self) -> None:
        if not self.issuer.strip() or not self.subject.strip() or not self.token_id.strip():
            raise ValueError("token issuer, subject and identifier are required")
        if not self.audience or any(not item.strip() for item in self.audience):
            raise ValueError("token audience must contain non-empty values")
        if len(set(self.audience)) != len(self.audience):
            raise ValueError("token audience values must be unique")
        for field in ("issued_at", "expires_at"):
            _require_aware(getattr(self, field), field)
        if self.not_before is not None:
            _require_aware(self.not_before, "not_before")
        if self.expires_at <= self.issued_at:
            raise ValueError("token validity window must end after issuance")
        if self.not_before is not None and (
            self.not_before < self.issued_at or self.not_before >= self.expires_at
        ):
            raise ValueError("token validity window has an invalid not-before time")
        if self.nonce is not None and not self.nonce.strip():
            raise ValueError("token nonce cannot be empty")
        if self.sender_key_thumbprint is not None and not re.fullmatch(
            r"[A-Za-z0-9_-]{43}", self.sender_key_thumbprint
        ):
            raise ValueError("sender key thumbprint must be a SHA-256 base64url value")

    def validate(
        self,
        *,
        expected_issuer: str,
        expected_audience: str,
        now: datetime | None = None,
        expected_nonce: str | None = None,
        expected_sender_key_thumbprint: str | None = None,
    ) -> None:
        current = now or datetime.now(UTC)
        _require_aware(current, "validation time")
        if not expected_issuer.strip() or not hmac.compare_digest(self.issuer, expected_issuer):
            raise PermissionError("token issuer is not trusted")
        if not expected_audience.strip() or expected_audience not in self.audience:
            raise PermissionError("token audience is not trusted")
        if current < self.issued_at or (self.not_before is not None and current < self.not_before):
            raise PermissionError("token is not yet valid")
        if current >= self.expires_at:
            raise PermissionError("token is outside its validity window")
        if expected_nonce is not None and (
            self.nonce is None or not hmac.compare_digest(self.nonce, expected_nonce)
        ):
            raise PermissionError("token nonce does not match the request")
        if self.sender_key_thumbprint is not None:
            if expected_sender_key_thumbprint is None:
                raise PermissionError("sender-bound token requires request key binding")
            if not hmac.compare_digest(self.sender_key_thumbprint, expected_sender_key_thumbprint):
                raise PermissionError("token sender key does not match the request")
        elif expected_sender_key_thumbprint is not None:
            raise PermissionError("token is missing the required sender key constraint")
