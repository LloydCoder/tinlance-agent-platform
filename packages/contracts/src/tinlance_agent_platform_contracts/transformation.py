"""Authority-side typed model for the canonical transformation/v1 contract.

Transformation is attributable intent/execution/outcome data. It is never an
authorization grant and does not replace Platform policy or execution controls.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

CONTRACT_VERSION = "transformation/v1"


class TransformationExecutionState(StrEnum):
    PLANNED = "planned"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PARTIAL = "partial"


class TransformationOutcomeStatus(StrEnum):
    UNKNOWN = "unknown"
    ACHIEVED = "achieved"
    PARTIALLY_ACHIEVED = "partially_achieved"
    NOT_ACHIEVED = "not_achieved"
    INCONCLUSIVE = "inconclusive"


class TransformationDataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


def _required(value: str, name: str) -> None:
    if not value or value != value.strip():
        raise ValueError(f"{name} is required and must be normalized")


def _date_time(value: str, name: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{name} must be an ISO-8601 date-time") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{name} must include a timezone")


@dataclass(frozen=True, slots=True)
class TransformationReference:
    ref: str
    kind: str
    digest: str | None = None

    def __post_init__(self) -> None:
        _required(self.ref, "reference ref")
        _required(self.kind, "reference kind")
        if self.digest is not None and (
            len(self.digest) != 64 or any(char not in "0123456789abcdef" for char in self.digest)
        ):
            raise ValueError("transformation digest must be lowercase SHA-256 hex")

    def as_payload(self) -> dict[str, str]:
        value = {"ref": self.ref, "kind": self.kind}
        if self.digest is not None:
            value["digest"] = self.digest
        return value


@dataclass(frozen=True, slots=True)
class TransformationCapability:
    capability_ref: str
    reason: str

    def __post_init__(self) -> None:
        _required(self.capability_ref, "capability_ref")
        _required(self.reason, "capability reason")

    def as_payload(self) -> dict[str, str]:
        return {"capability_ref": self.capability_ref, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class TransformationConstraints:
    deadline: str | None = None
    budget_ref: str | None = None
    data_classification: TransformationDataClassification | None = None
    resource_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.deadline is not None:
            _date_time(self.deadline, "deadline")
        if self.budget_ref is not None:
            _required(self.budget_ref, "budget_ref")
        if any(not ref.strip() for ref in self.resource_refs):
            raise ValueError("resource references must be non-empty")

    def as_payload(self) -> dict[str, Any]:
        value: dict[str, Any] = {}
        if self.deadline is not None:
            value["deadline"] = self.deadline
        if self.budget_ref is not None:
            value["budget_ref"] = self.budget_ref
        if self.data_classification is not None:
            value["data_classification"] = self.data_classification.value
        if self.resource_refs:
            value["resource_refs"] = list(self.resource_refs)
        return value


@dataclass(frozen=True, slots=True)
class TransformationMetric:
    name: str
    value: float | int | str | bool
    unit: str | None = None

    def __post_init__(self) -> None:
        _required(self.name, "metric name")

    def as_payload(self) -> dict[str, Any]:
        value: dict[str, Any] = {"name": self.name, "value": self.value}
        if self.unit is not None:
            value["unit"] = self.unit
        return value


@dataclass(frozen=True, slots=True)
class TransformationOutcome:
    status: TransformationOutcomeStatus
    achieved: bool
    metrics: tuple[TransformationMetric, ...] = ()
    business_effect_refs: tuple[str, ...] = ()
    failure_code: str | None = None

    def __post_init__(self) -> None:
        if self.status is TransformationOutcomeStatus.ACHIEVED and not self.achieved:
            raise ValueError("achieved outcome requires achieved=true")
        if self.achieved and self.status is not TransformationOutcomeStatus.ACHIEVED:
            raise ValueError("achieved=true requires achieved status")
        if any(not ref.strip() for ref in self.business_effect_refs):
            raise ValueError("business effect references must be non-empty")
        if self.failure_code is not None:
            _required(self.failure_code, "failure_code")

    def as_payload(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "status": self.status.value,
            "achieved": self.achieved,
            "metrics": [metric.as_payload() for metric in self.metrics],
            "business_effect_refs": list(self.business_effect_refs),
        }
        if self.failure_code is not None:
            value["failure_code"] = self.failure_code
        return value


@dataclass(frozen=True, slots=True)
class TransformationProvenance:
    declared_by: str
    recorded_at: str
    source_refs: tuple[str, ...] = ()
    content_digest: str | None = None

    def __post_init__(self) -> None:
        _required(self.declared_by, "declared_by")
        _date_time(self.recorded_at, "recorded_at")
        if any(not ref.strip() for ref in self.source_refs):
            raise ValueError("provenance source references must be non-empty")
        if self.content_digest is not None and (
            len(self.content_digest) != 64
            or any(char not in "0123456789abcdef" for char in self.content_digest)
        ):
            raise ValueError("provenance digest must be lowercase SHA-256 hex")

    def as_payload(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "declared_by": self.declared_by,
            "recorded_at": self.recorded_at,
            "source_refs": list(self.source_refs),
        }
        if self.content_digest is not None:
            value["content_digest"] = self.content_digest
        return value


@dataclass(frozen=True, slots=True)
class Transformation:
    transformation_id: UUID
    tenant_ref: str
    version: int
    principal_ref: str
    agent_ref: str
    agent_version: str
    workspace_ref: str
    task_ref: str
    objective: str
    requested_capabilities: tuple[TransformationCapability, ...]
    policy_refs: tuple[str, ...]
    risk_class: str
    execution_state: TransformationExecutionState
    success_criteria: tuple[str, ...] = ("Outcome to be verified",)
    business_metric: str | None = None
    delegated_by: str | None = None
    constraints: TransformationConstraints = TransformationConstraints()
    approval_refs: tuple[str, ...] = ()
    idempotency_key: str = ""
    run_ref: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    output_refs: tuple[TransformationReference, ...] = ()
    evidence_refs: tuple[TransformationReference, ...] = ()
    outcome: TransformationOutcome = TransformationOutcome(TransformationOutcomeStatus.UNKNOWN, False)
    provenance: TransformationProvenance = field(
        default_factory=lambda: TransformationProvenance(
            "agent-platform",
            datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        )
    )

    def __post_init__(self) -> None:
        if self.version < 1:
            raise ValueError("transformation version must be >= 1")
        for value, name in (
            (self.tenant_ref, "tenant_ref"),
            (self.principal_ref, "principal_ref"),
            (self.agent_ref, "agent_ref"),
            (self.agent_version, "agent_version"),
            (self.workspace_ref, "workspace_ref"),
            (self.task_ref, "task_ref"),
            (self.objective, "objective"),
            (self.risk_class, "risk_class"),
        ):
            _required(value, name)
        if not self.success_criteria or any(not item.strip() for item in self.success_criteria):
            raise ValueError("transformation requires non-empty success criteria")
        if not self.requested_capabilities:
            raise ValueError("transformation requires requested capabilities")
        if not self.policy_refs or any(not ref.strip() for ref in self.policy_refs):
            raise ValueError("transformation requires policy references")
        if any(not ref.strip() for ref in self.approval_refs):
            raise ValueError("approval references must be non-empty")
        if self.business_metric is not None:
            _required(self.business_metric, "business_metric")
        if self.delegated_by is not None:
            _required(self.delegated_by, "delegated_by")
        if not self.idempotency_key:
            object.__setattr__(
                self, "idempotency_key", f"transformation-{self.transformation_id}-v{self.version}"
            )
        if not 16 <= len(self.idempotency_key) <= 256:
            raise ValueError("idempotency key must contain 16 to 256 characters")
        if self.run_ref is not None:
            _required(self.run_ref, "run_ref")
        if self.started_at is not None:
            _date_time(self.started_at, "started_at")
        if self.completed_at is not None:
            _date_time(self.completed_at, "completed_at")
        if self.completed_at is not None and self.started_at is None:
            raise ValueError("completed_at requires started_at")

    def as_payload(self) -> dict[str, Any]:
        intent: dict[str, Any] = {
            "objective": self.objective,
            "success_criteria": list(self.success_criteria),
        }
        if self.business_metric is not None:
            intent["business_metric"] = self.business_metric
        actor: dict[str, Any] = {
            "principal_ref": self.principal_ref,
            "agent_ref": self.agent_ref,
            "agent_version": self.agent_version,
        }
        if self.delegated_by is not None:
            actor["delegated_by"] = self.delegated_by
        execution: dict[str, Any] = {
            "state": self.execution_state.value,
            "idempotency_key": self.idempotency_key,
        }
        if self.run_ref is not None:
            execution["run_ref"] = self.run_ref
        if self.started_at is not None:
            execution["started_at"] = self.started_at
        if self.completed_at is not None:
            execution["completed_at"] = self.completed_at
        governance: dict[str, Any] = {
            "policy_refs": list(self.policy_refs),
            "risk_class": self.risk_class,
        }
        if self.approval_refs:
            governance["approval_refs"] = list(self.approval_refs)
        return {
            "schema_version": CONTRACT_VERSION,
            "transformation_id": str(self.transformation_id),
            "version": self.version,
            "tenant_ref": self.tenant_ref,
            "intent": intent,
            "actor": actor,
            "context": {"workspace_ref": self.workspace_ref, "task_ref": self.task_ref},
            "requested_capabilities": [item.as_payload() for item in self.requested_capabilities],
            "constraints": self.constraints.as_payload(),
            "governance": governance,
            "execution": execution,
            "outputs": [item.as_payload() for item in self.output_refs],
            "evidence": [item.as_payload() for item in self.evidence_refs],
            "outcome": self.outcome.as_payload(),
            "provenance": self.provenance.as_payload(),
        }

    def content_digest(self) -> str:
        payload = self.as_payload()
        payload["provenance"] = dict(payload["provenance"])
        payload["provenance"].pop("content_digest", None)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        return hashlib.sha256(encoded).hexdigest()
