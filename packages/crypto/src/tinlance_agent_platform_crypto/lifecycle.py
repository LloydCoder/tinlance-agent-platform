"""Key lifecycle contracts; private key material remains external."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum


def _require_aware(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")


class KeyState(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class KeyVersion:
    key_id: str
    version: str
    algorithm: str
    state: KeyState
    activated_at: datetime
    retired_at: datetime | None = None
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        if not all(value.strip() for value in (self.key_id, self.version, self.algorithm)):
            raise ValueError("key lifecycle fields are required")
        if not isinstance(self.state, KeyState):
            raise ValueError("key state must be a supported KeyState")
        _require_aware(self.activated_at, "activated_at")
        if self.retired_at is not None:
            _require_aware(self.retired_at, "retired_at")
            if self.retired_at < self.activated_at:
                raise ValueError("retirement timestamp cannot precede activation")
        if self.revoked_at is not None:
            _require_aware(self.revoked_at, "revoked_at")
            if self.revoked_at < self.activated_at:
                raise ValueError("revocation timestamp cannot precede activation")
        if self.state is KeyState.ACTIVE and (
            self.retired_at is not None or self.revoked_at is not None
        ):
            raise ValueError("active keys cannot have retirement or revocation timestamps")
        if self.state is KeyState.RETIRED and (
            self.retired_at is None or self.revoked_at is not None
        ):
            raise ValueError("retired keys require a retirement timestamp only")
        if self.state is KeyState.REVOKED:
            if self.revoked_at is None:
                raise ValueError("revoked keys require a revocation timestamp")
            if self.retired_at is not None and self.revoked_at < self.retired_at:
                raise ValueError("revocation timestamp cannot precede retirement")

    def usable(self, *, now: datetime | None = None) -> bool:
        current = now or datetime.now(UTC)
        _require_aware(current, "current time")
        return self.state is KeyState.ACTIVE and self.activated_at <= current


@dataclass(frozen=True, slots=True)
class KeyLifecycle:
    versions: tuple[KeyVersion, ...]

    def __post_init__(self) -> None:
        if not self.versions:
            raise ValueError("key lifecycle must contain at least one version")
        identifiers = [(item.key_id, item.version) for item in self.versions]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("key lifecycle contains a duplicate key version")
        if len({item.key_id for item in self.versions}) != 1:
            raise ValueError("all versions in a lifecycle must belong to the same key")

    def active(self, *, now: datetime | None = None) -> KeyVersion:
        current = now or datetime.now(UTC)
        _require_aware(current, "current time")
        active = [version for version in self.versions if version.usable(now=current)]
        if len(active) != 1:
            raise RuntimeError("key lifecycle requires exactly one active usable key version")
        return active[0]
