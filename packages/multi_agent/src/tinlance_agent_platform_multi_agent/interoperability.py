"""Provider-neutral remote-agent interoperability contracts.

Discovery metadata is descriptive, not authoritative. Remote communication must
enter the normal Platform identity, authorization and execution boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class AgentSkill:
    skill_id: str
    description: str
    capabilities: frozenset[str]

    def __post_init__(self) -> None:
        if not self.skill_id or self.skill_id != self.skill_id.strip():
            raise ValueError("skill_id must be normalized")
        if not self.description.strip():
            raise ValueError("skill description is required")
        if any(
            not capability or capability != capability.strip()
            for capability in self.capabilities
        ):
            raise ValueError("skill capabilities must be normalized")


@dataclass(frozen=True, slots=True)
class AgentCard:
    agent_id: UUID
    protocol_version: str
    name: str
    description: str
    endpoint: str
    skills: tuple[AgentSkill, ...]
    authentication_schemes: tuple[str, ...]
    card_version: str
    signature: str | None = None

    def validate(self, *, require_https: bool = True) -> None:
        parsed = urlparse(self.endpoint)
        allowed_schemes = {"https"} if require_https else {"http", "https"}
        if parsed.scheme not in allowed_schemes or not parsed.netloc:
            raise ValueError("agent endpoint must use a valid secure URL")
        if not all(
            (self.protocol_version.strip(), self.name.strip(), self.card_version.strip())
        ):
            raise ValueError("agent card identity fields are required")
        if any(not scheme or scheme != scheme.strip() for scheme in self.authentication_schemes):
            raise ValueError("authentication schemes must be normalized")
        if any(
            "secret" in scheme.lower() or "api_key=" in scheme.lower()
            for scheme in self.authentication_schemes
        ):
            raise ValueError("agent cards must not contain credential material")
        if self.signature is not None and not self.signature.strip():
            raise ValueError("signature cannot be empty")


@dataclass(frozen=True, slots=True)
class RemoteDelegation:
    delegation_id: UUID
    tenant_id: str
    parent_agent_id: UUID
    remote_agent_id: UUID
    capabilities: frozenset[str]
    resource_scope: str
    delegation_nonce: str

    @classmethod
    def issue(
        cls,
        *,
        tenant_id: str,
        parent_agent_id: UUID,
        remote_agent_id: UUID,
        parent_capabilities: frozenset[str],
        requested_capabilities: frozenset[str],
        resource_scope: str,
    ) -> RemoteDelegation:
        if not requested_capabilities <= parent_capabilities:
            raise PermissionError("remote delegation cannot widen parent authority")
        if not tenant_id or tenant_id != tenant_id.strip() or not resource_scope.strip():
            raise ValueError("tenant and resource scope are required")
        return cls(
            uuid4(), tenant_id, parent_agent_id, remote_agent_id,
            requested_capabilities, resource_scope, str(uuid4()),
        )
