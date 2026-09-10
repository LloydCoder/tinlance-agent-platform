"""Security and execution contracts shared across platform layers."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum
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
    """Provider-neutral security principal; authentication adapters populate it."""

    subject_id: str
    principal_type: str
    tenant_id: str
    roles: frozenset[str] = frozenset()
    scopes: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Immutable authority context propagated across platform boundaries."""

    request_id: str
    tenant_id: str
    principal: Principal
    environment: str
    trace_id: str | None = None

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


@dataclass(frozen=True, slots=True)
class CapabilityRequest:
    action: str
    resource: str
    capabilities: frozenset[str]
    risk: RiskTier
    reversibility: Reversibility
    data_class: DataClass
    blast_radius: str
    parameters: dict[str, Any]


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
