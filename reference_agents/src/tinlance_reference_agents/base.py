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
    requested_timeout_seconds: float = 30.0
    requested_tool_calls: int = 1
    reversibility: str = "reversible"
    data_class: str = "internal"
    blast_radius: str = "single"
    sandbox_required: bool = False
    evidence_required: bool = True

    def __post_init__(self) -> None:
        if not self.action.strip() or not self.resource.strip() or not self.risk.strip():
            raise ValueError("tool plan fields are required")
        if self.requires_approval and self.risk == "prohibited":
            raise ValueError("prohibited actions cannot be made approvable")
        if self.requested_timeout_seconds <= 0 or self.requested_tool_calls < 1:
            raise ValueError("tool plan execution limits must be positive")
        if not self.reversibility.strip() or not self.data_class.strip() or not self.blast_radius.strip():
            raise ValueError("tool plan execution classifications are required")


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
    """Shared workflow composer; Platform remains the authority boundary."""

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
        approval_id: UUID | str | None = None,
        request_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> Execution:
        """Execute only through R10; security fields come from the immutable plan."""
        descriptor = plan.descriptor
        return self.client.tools.execute(
            agent_run.run.run_id,
            agent_run.run.agent_id,
            ToolInvocation(
                descriptor.name,
                descriptor.capability,
                plan.action,
                plan.resource,
                arguments or {},
            ),
            capability_version=descriptor.version,
            tool_version=descriptor.version,
            requested_timeout_seconds=plan.requested_timeout_seconds,
            requested_tool_calls=plan.requested_tool_calls,
            risk=plan.risk,
            reversibility=plan.reversibility,
            data_class=plan.data_class,
            blast_radius=plan.blast_radius,
            approval_id=approval_id,
            request_id=request_id,
            idempotency_key=idempotency_key,
            sandbox_required=plan.sandbox_required,
            evidence_required=plan.evidence_required,
        )

    def request_approval(
        self,
        agent_run: AgentRun,
        *,
        plan: ToolPlan,
        arguments: dict[str, Any] | None = None,
        reason: str,
        request_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> str:
        """Request approval bound to the exact R10 execution intent."""
        if not plan.requires_approval:
            raise ValueError("approval is not required for this tool plan")
        ref = self.client.approvals.request(
            agent_run.run.run_id,
            plan.action,
            plan.resource,
            reason,
            execution_intent=self._execution_intent(agent_run, plan, arguments),
            request_id=request_id,
            idempotency_key=idempotency_key,
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

    @staticmethod
    def _execution_intent(
        agent_run: AgentRun,
        plan: ToolPlan,
        arguments: dict[str, Any] | None,
    ) -> dict[str, Any]:
        descriptor = plan.descriptor
        return {
            "contract_version": "governed-execution.v1",
            "agent_id": str(agent_run.run.agent_id),
            "run_id": str(agent_run.run.run_id),
            "capability_id": descriptor.capability,
            "capability_version": descriptor.version,
            "tool_name": descriptor.name,
            "tool_version": descriptor.version,
            "action": plan.action,
            "resource": plan.resource,
            "input": arguments or {},
            "requested_timeout_seconds": plan.requested_timeout_seconds,
            "requested_tool_calls": plan.requested_tool_calls,
            "risk": plan.risk,
            "reversibility": plan.reversibility,
            "data_class": plan.data_class,
            "blast_radius": plan.blast_radius,
            "sandbox_required": plan.sandbox_required,
            "evidence_required": plan.evidence_required,
        }


def reject_untrusted_instructions(content: str) -> str:
    """Return untrusted content as data; never reinterpret it as authority."""
    if not isinstance(content, str):
        raise TypeError("untrusted content must be text")
    return content
