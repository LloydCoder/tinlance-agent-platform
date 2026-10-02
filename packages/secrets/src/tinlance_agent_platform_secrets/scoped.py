"""Execution-scoped secret handles.

A secret reference is intentionally useless outside the exact execution scope
for which it was issued. The external provider remains responsible for actual
secret storage, cryptographic protection and rotation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID


@dataclass(frozen=True, slots=True)
class ScopedSecretHandle:
    name: str
    version: str
    tenant_id: str
    principal_id: str
    agent_id: UUID
    execution_id: UUID
    capability_id: str

    def validate_scope(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        agent_id: UUID,
        execution_id: UUID,
        capability_id: str,
    ) -> None:
        if (
            self.tenant_id != tenant_id
            or self.principal_id != principal_id
            or self.agent_id != agent_id
            or self.execution_id != execution_id
            or self.capability_id != capability_id
        ):
            raise PermissionError("secret handle scope does not match execution authority")
        if not self.name or not self.version:
            raise ValueError("secret handle must be versioned")


class ScopedSecretProvider(Protocol):
    def resolve(self, handle: ScopedSecretHandle) -> str: ...


class ScopedSecretBroker:
    def __init__(self, provider: ScopedSecretProvider) -> None:
        self._provider = provider

    def resolve_for_execution(
        self,
        handle: ScopedSecretHandle,
        *,
        tenant_id: str,
        principal_id: str,
        agent_id: UUID,
        execution_id: UUID,
        capability_id: str,
    ) -> str:
        handle.validate_scope(
            tenant_id=tenant_id,
            principal_id=principal_id,
            agent_id=agent_id,
            execution_id=execution_id,
            capability_id=capability_id,
        )
        return self._provider.resolve(handle)
