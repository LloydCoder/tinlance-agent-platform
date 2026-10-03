"""Provider-neutral cryptographic contracts; key material stays external."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class KeyRef:
    key_id: str
    version: str
    algorithm: str

    def __post_init__(self) -> None:
        if not all(value.strip() for value in (self.key_id, self.version, self.algorithm)):
            raise ValueError("key reference fields are required")


@dataclass(frozen=True, slots=True)
class SignatureEnvelope:
    key: KeyRef
    payload_digest: str
    signature: str

    def __post_init__(self) -> None:
        if not self.payload_digest.strip() or not self.signature.strip():
            raise ValueError("signature envelope requires digest and signature")

    def validate_digest(self) -> None:
        if not self.payload_digest.startswith(("sha256:", "sha384:", "sha512:")):
            raise ValueError("payload digest must be algorithm-qualified")
