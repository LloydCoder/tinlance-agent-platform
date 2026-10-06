"""Execution-scoped secret handles.

A secret reference is intentionally useless outside the exact execution scope
for which it was issued. The external provider remains responsible for actual
secret storage, cryptographic protection and rotation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
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
    purpose: str
    audience: str
    issued_at: datetime
    expires_at: datetime

    def validate_scope(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        agent_id: UUID,
        execution_id: UUID,
        capability_id: str,
        purpose: str,
        audience: str,
        now: datetime | None = None,
    ) -> None:
        if (
            self.tenant_id != tenant_id
            or self.principal_id != principal_id
            or self.agent_id != agent_id
            or self.execution_id != execution_id
            or self.capability_id != capability_id
            or self.purpose != purpose
            or self.audience != audience
        ):
            raise PermissionError("secret handle scope does not match execution authority")
        if not self.name or not self.version or not self.purpose or not self.audience:
            raise ValueError("secret handle requires version, purpose and audience")
        current = now or datetime.now(UTC)
        if current.tzinfo is None:
            raise ValueError("secret validation time must be timezone-aware")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("secret handle timestamps must be timezone-aware")
        if (
            self.expires_at <= self.issued_at
            or current < self.issued_at
            or current >= self.expires_at
        ):
            raise PermissionError("secret handle is expired or not yet valid")


class SecretResolutionError(RuntimeError):
    """Provider failure without exposing backend or secret details."""


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
        purpose: str,
        audience: str,
        now: datetime | None = None,
    ) -> str:
        handle.validate_scope(
            tenant_id=tenant_id,
            principal_id=principal_id,
            agent_id=agent_id,
            execution_id=execution_id,
            capability_id=capability_id,
            purpose=purpose,
            audience=audience,
            now=now,
        )
        try:
            return self._provider.resolve(handle)
        except PermissionError:
            raise
        except Exception as exc:
            raise SecretResolutionError("secret provider resolution failed") from exc
