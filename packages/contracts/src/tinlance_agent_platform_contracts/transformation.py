"""Authority-side Transformation contract.

The Transformation record is attributable execution context and outcome data.
It never substitutes for authentication, authorization, policy, approval, budget,
sandbox, secret, or final side-effect enforcement.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from uuid import UUID


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


@dataclass(frozen=True, slots=True)
class TransformationReference:
    ref: str
    kind: str
    digest: str | None = None

    def __post_init__(self) -> None:
        if not self.ref.strip() or not self.kind.strip():
            raise ValueError("transformation references require ref and kind")
        if self.digest is not None and (
            len(self.digest) != 64 or any(char not in "0123456789abcdef" for char in self.digest)
        ):
            raise ValueError("transformation digest must be lowercase SHA-256 hex")


@dataclass(frozen=True, slots=True)
class TransformationOutcome:
    status: TransformationOutcomeStatus
    achieved: bool
    metrics: tuple[tuple[str, Any], ...] = ()
    business_effect_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status is TransformationOutcomeStatus.ACHIEVED and not self.achieved:
            raise ValueError("achieved outcome requires achieved=true")


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
    requested_capability_refs: tuple[str, ...]
    policy_refs: tuple[str, ...]
    risk_class: str
    execution_state: TransformationExecutionState
    run_ref: str | None = None
    output_refs: tuple[TransformationReference, ...] = ()
    evidence_refs: tuple[TransformationReference, ...] = ()
    outcome: TransformationOutcome | None = None

    def __post_init__(self) -> None:
        values = (
            self.tenant_ref,
            self.principal_ref,
            self.agent_ref,
            self.agent_version,
            self.workspace_ref,
            self.task_ref,
            self.objective,
            self.risk_class,
        )
        if self.version < 1 or any(not value.strip() for value in values):
            raise ValueError("transformation identity and governance fields are required")
        if not self.requested_capability_refs:
            raise ValueError("transformation must reference requested capabilities")
        if not self.policy_refs:
            raise ValueError("transformation must reference policy")
