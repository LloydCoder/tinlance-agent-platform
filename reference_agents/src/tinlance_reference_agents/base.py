"""Shared domain behavior; Platform authority remains entirely server-side."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol
from uuid import UUID

from tinlance_agent_platform_sdk import (
    AgentPlatform,
    Event,
    EvidenceRef,
    Execution,
    Run,
    ToolContractRegistry,
    ToolDescriptor,
    ToolInvocation,
)


@dataclass(frozen=True, slots=True)
class WorkflowStep:
    name: str
    purpose: str
    consequential: bool = False
    requires_approval: bool = False

    def __post_init__(self) -> None:
        if not self.name.strip() or not self.purpose.strip():
            raise ValueError("workflow step requires name and purpose")
        if self.requires_approval and not self.consequential:
            raise ValueError("approval is meaningful only for consequential steps")


@dataclass(frozen=True, slots=True)
class ToolPlan:
    descriptor: ToolDescriptor
    action: str
    resource: str
    risk: str
    requires_approval: bool

    def __post_init__(self) -> None:
        if not self.action.strip() or not self.resource.strip() or not self.risk.strip():
            raise ValueError("tool plan fields are required")
        if self.requires_approval and self.risk == "prohibited":
            raise ValueError("prohibited actions cannot be made approvable")


@dataclass(frozen=True, slots=True)
class AgentRun:
    run: Run
    objective: str
    workflow: tuple[WorkflowStep, ...]
    planned_tools: tuple[ToolPlan, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class DomainFinding:
    statement: str
    classification: str
    confidence: str
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.statement.strip():
            raise ValueError("finding statement is required")
        if not self.evidence_ids and self.classification == "finding":
            raise ValueError("authoritative findings require evidence references")


@dataclass(frozen=True, slots=True)
class EvidenceBackedConclusion:
    conclusion: str
    evidence: tuple[EvidenceRef, ...]
    uncertainty: str

    def __post_init__(self) -> None:
        if not self.conclusion.strip() or not self.uncertainty.strip():
            raise ValueError("conclusion and uncertainty are required")


class PlatformClient(Protocol):
    runs: object
    approvals: object

    def capabilities(self, agent_id: UUID | str) -> tuple[object, ...]: ...


class ReferenceAgent:
    """Base workflow composer.

    This class intentionally knows only the public SDK contract. It never reaches
    into Platform implementation packages and never executes a tool locally.
    """

    name = "reference-agent"
    version = "0.1.0"

    def __init__(
        self,
        client: AgentPlatform,
        *,
        tool_registry: ToolContractRegistry | None = None,
    ):
        self.client = client
        self.tools = tool_registry or ToolContractRegistry()

    def start(
        self,
        *,
        task_id: UUID | str,
        agent_id: UUID | str,
        objective: str,
        workflow: tuple[WorkflowStep, ...],
        planned_tools: tuple[ToolPlan, ...] = (),
        request_id: str | None = None,
    ) -> AgentRun:
        if not objective.strip():
            raise ValueError("objective is required")
        run = self.client.runs.create(
            task_id,
            agent_id,
            self._intent(objective, workflow),
            request_id=request_id,
        )
        return AgentRun(run, objective, workflow, planned_tools)

    def execute_tool(
        self,
        agent_run: AgentRun,
        *,
        plan: ToolPlan,
        arguments: dict[str, Any] | None = None,
        capability_version: str | None = None,
        risk: str = "low",
        reversibility: str = "reversible",
        data_class: str = "internal",
        blast_radius: str = "single",
        approval_id: UUID | str | None = None,
        request_id: str | None = None,
        idempotency_key: str | None = None,
        sandbox_required: bool = False,
        evidence_required: bool = True,
    ) -> Execution:
        """Request consequential execution through the external Platform SDK only."""
        descriptor = plan.descriptor
        return self.client.tools.execute(
            agent_run.run.run_id,
            agent_run.run.agent_id,
            ToolInvocation(
                descriptor.name, descriptor.capability, plan.action, plan.resource, arguments or {},
            ),
            capability_version=capability_version or descriptor.version,
            tool_version=descriptor.version,
            requested_timeout_seconds=30.0,
            risk=risk,
            reversibility=reversibility,
            data_class=data_class,
            blast_radius=blast_radius,
            approval_id=approval_id,
            request_id=request_id,
            idempotency_key=idempotency_key,
            sandbox_required=sandbox_required,
            evidence_required=evidence_required,
        )

    def request_approval(
        self,
        agent_run: AgentRun,
        *,
        action: str,
        resource: str,
        reason: str,
        request_id: str | None = None,
    ) -> str:
        ref = self.client.approvals.request(
            agent_run.run.run_id,
            action,
            resource,
            reason,
            request_id=request_id,
        )
        return str(ref.approval_id)

    def collect(self, agent_run: AgentRun) -> tuple[tuple[Event, ...], tuple[EvidenceRef, ...]]:
        return (
            self.client.runs.events(agent_run.run.run_id),
            self.client.runs.evidence(agent_run.run.run_id),
        )

    @staticmethod
    def _intent(objective: str, workflow: tuple[WorkflowStep, ...]) -> str:
        steps = ", ".join(step.name for step in workflow)
        return f"objective:{objective.strip()}|workflow:{steps}"


def reject_untrusted_instructions(content: str) -> str:
    """Return untrusted content as data; never reinterpret it as agent instructions.

    This function deliberately performs no 'prompt sanitization'. The security
    boundary is architectural: untrusted content is never used as authority.
    """
    if not isinstance(content, str):
        raise TypeError("untrusted content must be text")
    return content
