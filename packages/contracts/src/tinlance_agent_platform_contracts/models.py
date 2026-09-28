"""Security and execution vocabulary shared across platform layers."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Any
from uuid import UUID


class AutonomyLevel(IntEnum):
    OBSERVATION = 0
    ANALYSIS = 1
    RECOMMENDATION = 2
    SIMULATION = 3
    LOW_RISK_EXECUTION = 4
    SUPERVISED_EXECUTION = 5
    CONDITIONAL_AUTONOMY = 6
    HIGH_AUTONOMY = 7


class RiskTier(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    PROHIBITED = "prohibited"


class Reversibility(StrEnum):
    REVERSIBLE = "reversible"
    PARTIALLY_REVERSIBLE = "partially_reversible"
    IRREVERSIBLE = "irreversible"


class DataClass(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SENSITIVE = "sensitive"
    RESTRICTED = "restricted"
    SECRET = "secret"


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True, slots=True)
class Principal:
    subject_id: str
    principal_type: str
    tenant_id: str
    roles: frozenset[str] = frozenset()
    scopes: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        values = (self.subject_id, self.principal_type, self.tenant_id)
        if not all(values) or any(value != value.strip() for value in values):
            raise ValueError("principal identity fields must be normalized and non-empty")
        if any(not scope or scope != scope.strip() for scope in self.scopes):
            raise ValueError("principal scopes must be normalized")
        if any(not role or role != role.strip() for role in self.roles):
            raise ValueError("principal roles must be normalized")


@dataclass(frozen=True, slots=True)
class RequestContext:
    request_id: str
    tenant_id: str
    principal: Principal
    environment: str
    trace_id: str | None = None

    def __post_init__(self) -> None:
        if not self.request_id or not self.tenant_id or not self.environment:
            raise ValueError("request context fields must be non-empty")
        if self.request_id != self.request_id.strip() or self.tenant_id != self.tenant_id.strip():
            raise ValueError("request context identifiers must be normalized")
        if self.principal.tenant_id != self.tenant_id:
            raise ValueError("principal and request context tenants must match")

    def assert_tenant(self, tenant_id: str) -> None:
        if self.tenant_id != tenant_id:
            raise PermissionError("cross-tenant context is forbidden")


@dataclass(frozen=True, slots=True)
class AgentIdentity:
    agent_id: UUID
    tenant_id: str
    agent_type: str
    version: str
    owner_subject_id: str
    policy_profile: str
    trust_level: str
    environment: str

    def __post_init__(self) -> None:
        values = (
            self.tenant_id,
            self.agent_type,
            self.version,
            self.owner_subject_id,
            self.policy_profile,
            self.trust_level,
            self.environment,
        )
        if not all(values) or any(value != value.strip() for value in values):
            raise ValueError("agent identity fields must be normalized and non-empty")


@dataclass(frozen=True, slots=True)
class CapabilityRequest:
    action: str
    resource: str
    capabilities: frozenset[str]
    risk: RiskTier
    reversibility: Reversibility
    data_class: DataClass
    blast_radius: str
    parameters: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.action or not self.resource or not self.capabilities or not self.blast_radius:
            raise ValueError("capability request fields must be non-empty")
        if any(value != value.strip() for value in (self.action, self.resource, self.blast_radius)):
            raise ValueError("capability request fields must be normalized")
        capabilities = self.capabilities
        if any(not capability or capability != capability.strip() for capability in capabilities):
            raise ValueError("capability names must be normalized")
        if self.data_class is DataClass.SECRET:
            raise ValueError("secret data cannot be a normal capability payload")
        if len(self.parameters) > 64:\n            raise ValueError("capability parameters are too large")\n        object.__setattr__(self, "parameters", _freeze(self.parameters))


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    decision: Decision
    policy_id: str
    policy_version: str
    reason: str
    risk: RiskTier
    requires_approval: bool = False


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    evidence_id: UUID
    task_id: UUID
    action_id: str
    content_hash: str
    source: str
    provenance: str
    classification: DataClass


@dataclass(frozen=True, slots=True)
class AuditRecord:
    record_id: UUID
    tenant_id: str
    actor_id: str
    actor_type: str
    action: str
    resource: str
    policy_id: str
    policy_version: str
    decision: Decision
    result: str
    timestamp: str
