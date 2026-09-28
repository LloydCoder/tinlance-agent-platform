from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class SecretHandle:
    name: str
    version: str


class SecretProvider(Protocol):
    def resolve(self, handle: SecretHandle) -> str: ...


class SecretBroker:
    def __init__(self, provider: SecretProvider) -> None:
        self._provider = provider

    def resolve_for_execution(self, handle: SecretHandle) -> str:
        if not handle.name or not handle.version:
            raise ValueError("secret handle must be versioned")
        return self._provider.resolve(handle)
