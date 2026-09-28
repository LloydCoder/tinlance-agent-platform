"""Tenant-owned durable domain vocabulary."""
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID
class CustomerStatus(StrEnum): ACTIVE="active"; SUSPENDED="suspended"; ARCHIVED="archived"
class ProjectStatus(StrEnum): ACTIVE="active"; PAUSED="paused"; ARCHIVED="archived"
class RepositoryStatus(StrEnum): ACTIVE="active"; DISABLED="disabled"; ARCHIVED="archived"
class AssessmentStatus(StrEnum): CREATED="created"; QUEUED="queued"; RUNNING="running"; COMPLETED="completed"; FAILED="failed"; CANCELLED="cancelled"
class FindingStatus(StrEnum): OPEN="open"; CONFIRMED="confirmed"; REMEDIATED="remediated"; FALSE_POSITIVE="false_positive"; ACCEPTED_RISK="accepted_risk"
@dataclass(frozen=True, slots=True)
class Customer: customer_id: UUID; tenant_id: UUID; name: str; status: CustomerStatus = CustomerStatus.ACTIVE
@dataclass(frozen=True, slots=True)
class Project: project_id: UUID; tenant_id: UUID; customer_id: UUID; name: str; status: ProjectStatus = ProjectStatus.ACTIVE
@dataclass(frozen=True, slots=True)
class Repository: repository_id: UUID; tenant_id: UUID; project_id: UUID; provider: str; external_id: str; name: str; status: RepositoryStatus = RepositoryStatus.ACTIVE
@dataclass(frozen=True, slots=True)
class Assessment: assessment_id: UUID; tenant_id: UUID; repository_id: UUID; idempotency_key: str; kind: str; status: AssessmentStatus = AssessmentStatus.CREATED; parent_assessment_id: UUID | None = None
@dataclass(frozen=True, slots=True)
class Finding: finding_id: UUID; tenant_id: UUID; assessment_id: UUID; fingerprint: str; title: str; severity: str; status: FindingStatus = FindingStatus.OPEN; parent_finding_id: UUID | None = None
@dataclass(frozen=True, slots=True)
class Evidence: evidence_id: UUID; tenant_id: UUID; assessment_id: UUID; finding_id: UUID | None; source: str; content_hash: str; provenance: str