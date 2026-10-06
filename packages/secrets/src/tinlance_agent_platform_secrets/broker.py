"""Legacy secret broker compatibility shim.

Consequential secret resolution must use ScopedSecretBroker. This module
intentionally refuses unscoped resolution so older integrations cannot silently
bypass tenant, execution, capability, purpose, audience and time controls.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SecretHandle:
    name: str
    version: str


class SecretProvider:
    """Compatibility protocol marker; use ScopedSecretProvider for execution."""

    def resolve(self, handle: SecretHandle) -> str:
        raise NotImplementedError


class SecretBroker:
    def __init__(self, provider: SecretProvider) -> None:
        self._provider = provider

    def resolve_for_execution(self, handle: SecretHandle) -> str:
        raise PermissionError(
            "unscoped secret resolution is disabled; use ScopedSecretBroker"
        )
