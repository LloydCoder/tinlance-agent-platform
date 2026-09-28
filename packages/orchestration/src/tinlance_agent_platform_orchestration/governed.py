from dataclasses import dataclass
from uuid import UUID

from tinlance_agent_platform_authorization import authorize\nfrom tinlance_agent_platform_budgets import BudgetService
from tinlance_agent_platform_contracts import (
    CapabilityRequest,
    Decision,
    RequestContext,
    Run,
    TaskSpec,
    ToolCall,
)
from tinlance_agent_platform_events import EventStore, new_event
from tinlance_agent_platform_evidence import EvidenceStore
from tinlance_agent_platform_models import ModelGateway, ModelRequest, ModelResponse
from tinlance_agent_platform_observability import ObservabilitySink, new_security_event
from tinlance_agent_platform_tools.gateway import ApprovalVerifier, ToolGateway
from tinlance_agent_platform_trajectory import TrajectoryStore


@dataclass(frozen=True, slots=True)
class GovernedExecutionResult:
    run: Run
    model_response: ModelResponse
    tool_output: str
    evidence_id: UUID


class GovernedExecutionService:
    """Reference end-to-end path enforcing authority before every side effect."""

    def __init__(
        self,
        model_gateway: ModelGateway,
        tool_gateway: ToolGateway,
        events: EventStore,
        evidence: EvidenceStore,
        trajectory: TrajectoryStore,
        observability: ObservabilitySink,
    ) -> None:
        self._models = model_gateway
        self._tools = tool_gateway
        self._events = events
        self._evidence = evidence
        self._trajectory = trajectory
        self._observability = observability

    def execute(
        self,
        context: RequestContext,
        task: TaskSpec,
        run: Run,
        model_provider: str,
        model_request: ModelRequest,
        capability_request: CapabilityRequest,
        tool_call: ToolCall,
    ) -> GovernedExecutionResult:
        if (
            run.tenant_id != context.tenant_id
            or task.tenant_id != context.tenant_id
            or model_request.tenant_id != context.tenant_id
            or tool_call.tenant_id != context.tenant_id
            or tool_call.run_id != run.run_id
            or run.task_id != task.task_id
        ):
            raise PermissionError("governed execution tenant or identity mismatch")

        running = self._state.transition(run, RunStatus.RUNNING)\n        self._budget.consume_turn(0.0)\n        started = monotonic()\n\n        decision = authorize(context, capability_request)
        if decision.decision is Decision.DENY:
            self._observability.emit_security(
                new_security_event(
                    context.tenant_id,
                    "authorization.denied",
                    "warning",
                    actor_id=context.principal.subject_id,
                    trace_id=context.trace_id,
                    outcome="deny",
                )
            )
            raise PermissionError(decision.reason)

        model_response = self._models.complete(model_provider, model_request)\n        elapsed = monotonic() - started\n        if elapsed > self._budget.budget.max_seconds:\n            raise TimeoutError("runtime budget exceeded before side effects")
        self._events.append(
            new_event(
                context.tenant_id,
                run.run_id,
                "model.completed",
                {"outcome": "allow", "model": model_response.model},
            )
        )
        self._trajectory.append(
            context.tenant_id, run.run_id, "model.completed", model_response.output
        )

        self._budget.consume_tool_call()\n        tool_decision = self._tools.authorize(context, tool_call, capability_request)
        tool_output = self._tools.execute(\n            tool_call,\n            tool_decision,\n            approval_id=approval_id,\n            approval_verifier=approval_verifier,\n        )
        evidence = self._evidence.append(context.tenant_id, run.run_id, tool_output)
        self._events.append(
            new_event(
                context.tenant_id,
                run.run_id,
                "tool.executed",
                {"outcome": "allow", "evidence_id": str(evidence.evidence_id)},
            )
        )
        self._trajectory.append(
            context.tenant_id, run.run_id, "evidence.created", evidence.content_hash
        )
        self._observability.emit_security(
            new_security_event(
                context.tenant_id,
                "tool.executed",
                "info",
                actor_id=context.principal.subject_id,
                trace_id=context.trace_id,
                outcome="allow",
            )
        )
        completed = self._state.transition(running, RunStatus.SUCCEEDED)\n        return GovernedExecutionResult(\n            completed, model_response, tool_output, evidence.evidence_id\n        )
