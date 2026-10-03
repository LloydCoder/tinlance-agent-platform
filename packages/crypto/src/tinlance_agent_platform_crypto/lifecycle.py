"""Key lifecycle contracts; private key material remains external."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum


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

    def __post_init__(self) -> None:
        if not all(value.strip() for value in (self.key_id, self.version, self.algorithm)):
            raise ValueError("key lifecycle fields are required")
        if self.state is KeyState.ACTIVE and self.retired_at is not None:
            raise ValueError("active keys cannot have a retirement timestamp")

    def usable(self, *, now: datetime | None = None) -> bool:
        current = now or datetime.now(UTC)
        if self.state is not KeyState.ACTIVE:
            return False
        return self.activated_at <= current


@dataclass(frozen=True, slots=True)
class KeyLifecycle:
    versions: tuple[KeyVersion, ...]

    def active(self) -> KeyVersion:
        active = [version for version in self.versions if version.state is KeyState.ACTIVE]
        if len(active) != 1:
            raise RuntimeError("key lifecycle requires exactly one active version")
        return active[0]
