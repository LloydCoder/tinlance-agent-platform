"""Tenant-scoped inventory metadata for governed platform resources."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID


class ResourceKind(StrEnum):
    AGENT = "agent"
    TOOL = "tool"
    MCP_SERVER = "mcp_server"
    MODEL = "model"
    POLICY = "policy"
    RUNTIME = "runtime"
    REMOTE_AGENT = "remote_agent"


class ResourceState(StrEnum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class ResourceRecord:
    resource_id: UUID
    tenant_id: str
    kind: ResourceKind
    name: str
    version: str
    state: ResourceState = ResourceState.ACTIVE
    owner: str = ""
    provenance: str = ""

    def __post_init__(self) -> None:
        if not self.tenant_id.strip() or not self.name.strip() or not self.version.strip():
            raise ValueError("resource tenant, name and version are required")
        if not self.owner.strip():
            raise ValueError("resource owner is required")

    def assert_tenant(self, tenant_id: str) -> None:
        if tenant_id != self.tenant_id:
            raise PermissionError("resource belongs to another tenant")

    @property
    def executable(self) -> bool:
        return self.state is ResourceState.ACTIVE
