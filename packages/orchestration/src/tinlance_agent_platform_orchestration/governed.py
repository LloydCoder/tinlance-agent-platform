from dataclasses import dataclass
from uuid import UUID

from tinlance_agent_platform_authorization import authorize
from tinlance_agent_platform_budgets import BudgetService
from tinlance_agent_platform_contracts import (
    CapabilityRequest,
    Decision,
    RequestContext,
    Run,
    RunStatus,
    TaskSpec,
    ToolCall,
)
from tinlance_agent_platform_events import EventStore, new_event
from tinlance_agent_platform_evidence import EvidenceStore
from tinlance_agent_platform_models import ModelGateway, ModelRequest, ModelResponse
from tinlance_agent_platform_observability import ObservabilitySink, new_security_event
from tinlance_agent_platform_runtime import ExecutionTimeout, RunStateMachine, call_with_timeout
from tinlance_agent_platform_tools.gateway import ApprovalVerifier, ToolGateway
from tinlance_agent_platform_trajectory import TrajectoryStore


@dataclass(frozen=True, slots=True)
class GovernedExecutionResult:
    run: Run
    model_response: ModelResponse
    tool_output: str
    evidence_id: UUID


class GovernedExecutionService:
    """Reference end-to-end execution path for the canonical authority chain."""

    def __init__(
        self,
        model_gateway: ModelGateway,
        tool_gateway: ToolGateway,
        budget_service: BudgetService,
        events: EventStore,
        evidence: EvidenceStore,
        trajectory: TrajectoryStore,
        observability: ObservabilitySink,
    ) -> None:
        self._models = model_gateway
        self._tools = tool_gateway
        self._budget = budget_service
        self._events = events
        self._evidence = evidence
        self._trajectory = trajectory
        self._observability = observability
        self._state = RunStateMachine()

    def execute(
        self,
        context: RequestContext,
        task: TaskSpec,
        run: Run,
        model_provider: str,
        model_request: ModelRequest,
        capability_request: CapabilityRequest,
        tool_call: ToolCall,
        *,
        approval_id: UUID | None = None,
        approval_verifier: ApprovalVerifier | None = None,
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

        decision = authorize(context, capability_request)
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

        running = self._state.transition(run, RunStatus.RUNNING)
        remaining_budget = self._budget.budget.max_seconds - self._budget.budget.elapsed_seconds
        timeout_seconds = min(task.timeout_seconds, remaining_budget)
        if timeout_seconds <= 0:
            self._state.transition(
                running, RunStatus.FAILED, failure_code="runtime_budget_exceeded"
            )
            raise TimeoutError("runtime budget exhausted before model execution")

        try:
            model_response, elapsed = call_with_timeout(
                lambda: self._models.complete(model_provider, model_request), timeout_seconds
            )
        except ExecutionTimeout as exc:
            self._budget.consume_turn(timeout_seconds)
            self._state.transition(running, RunStatus.FAILED, failure_code="runtime_timeout")
            self._observability.emit_security(
                new_security_event(
                    context.tenant_id,
                    "runtime.timeout",
                    "warning",
                    actor_id=context.principal.subject_id,
                    trace_id=context.trace_id,
                    outcome="deny",
                )
            )
            raise TimeoutError("model execution exceeded its wall-clock deadline") from exc

        self._budget.consume_turn(elapsed)
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

        self._budget.consume_tool_call()
        tool_decision = self._tools.authorize(context, tool_call, capability_request)
        permit = self._tools.issue_permit(tool_call, tool_decision)
        tool_output = self._tools.execute(
            tool_call,
            permit,
            approval_id=approval_id,
            approval_verifier=approval_verifier,
        )
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
        completed = self._state.transition(running, RunStatus.SUCCEEDED)
        return GovernedExecutionResult(completed, model_response, tool_output, evidence.evidence_id)
