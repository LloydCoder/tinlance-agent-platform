"""Execution-scoped credentials for model-provider adapters.

This module depends on the Platform secret broker and a structural request protocol,
not on the models package, preserving the package dependency boundary.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID

from .scoped import ScopedSecretBroker, ScopedSecretHandle


class ModelCredentialRequest(Protocol):
    tenant_id: str
    principal_id: str | None
    agent_id: str
    execution_id: UUID | None
    capability_id: str | None


@dataclass(frozen=True, slots=True)
class ScopedModelCredentialProvider:
    """Resolve a model token only for the exact Platform execution scope."""

    broker: ScopedSecretBroker = field(repr=False)
    handle: ScopedSecretHandle = field(repr=False)

    def token(self, request: ModelCredentialRequest) -> str:
        if (
            request.principal_id is None
            or request.execution_id is None
            or request.capability_id is None
        ):
            raise PermissionError("model request lacks execution-scoped credential context")
        if (
            request.tenant_id != self.handle.tenant_id
            or request.principal_id != self.handle.principal_id
            or request.agent_id != str(self.handle.agent_id)
            or request.execution_id != self.handle.execution_id
            or request.capability_id != self.handle.capability_id
        ):
            raise PermissionError("model credential scope does not match the request")
        return self.broker.resolve_for_execution(
            self.handle,
            tenant_id=request.tenant_id,
            principal_id=request.principal_id,
            agent_id=self.handle.agent_id,
            execution_id=request.execution_id,
            capability_id=request.capability_id,
            purpose=self.handle.purpose,
            audience=self.handle.audience,
        )
