from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from time import monotonic
from uuid import UUID, uuid4

from tinlance_agent_platform_approvals import ApprovalService
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
from tinlance_agent_platform_models import ModelGateway, ModelRequest
from tinlance_agent_platform_observability import ObservabilitySink, TraceSpan
from tinlance_agent_platform_runtime import RunStateMachine
from tinlance_agent_platform_tools import ToolGateway
from tinlance_agent_platform_trajectory import TrajectoryStore


@dataclass(frozen=True, slots=True)
class GovernedRunResult:
    run: Run
    output: str
    approval_id: UUID | None = None


class GovernedRunService:
    def __init__(
        self,
        models: ModelGateway,
        tools: ToolGateway,
        approvals: ApprovalService,
        budget: BudgetService,
        events: EventStore,
        trajectory: TrajectoryStore,
        observability: ObservabilitySink,
        model_provider: str,
    ) -> None:
        self._models = models
        self._tools = tools
        self._approvals = approvals
        self._budget = budget
        self._events = events
        self._trajectory = trajectory
        self._observability = observability
        self._provider = model_provider
        self._state = RunStateMachine()

    def run(
        self,
        context: RequestContext,
        run: Run,
        task: TaskSpec,
        model: str,
        messages: tuple[dict[str, str], ...],
        capability_for_tool: Callable[[ToolCall], CapabilityRequest],
    ) -> GovernedRunResult:
        if context.tenant_id != run.tenant_id or task.tenant_id != run.tenant_id:
            raise PermissionError("run, task and context tenants must match")
        if run.status is not RunStatus.CREATED:
            raise ValueError("run must start in created state")
        started = monotonic()
        running = self._state.transition(run, RunStatus.RUNNING)
        self._events.append_once(
            new_event(run.tenant_id, run.run_id, "run.started", {}, str(run.run_id))
        )
        self._trajectory.append(run.tenant_id, run.run_id, "run.started", "{}")
        try:
            response = self._models.complete(
                self._provider, ModelRequest(run.tenant_id, str(task.agent_id), model, messages)
            )
            self._budget.consume_turn(monotonic() - started)
            for call in response.tool_calls:
                decision = self._tools.authorize(context, call, capability_for_tool(call))
                if decision.decision is Decision.DENY:
                    failed = self._state.transition(
                        running, RunStatus.FAILED, failure_code="tool_denied"
                    )
                    self._events.append_once(
                        new_event(
                            run.tenant_id, run.run_id, "tool.denied", {"tool": call.tool_name}
                        )
                    )
                    return GovernedRunResult(failed, "")
                if decision.requires_approval:
                    approval = self._approvals.request(
                        run.tenant_id,
                        run.run_id,
                        call.action,
                        call.resource,
                        decision.reason,
                        context.principal.subject_id,
                    )
                    return GovernedRunResult(
                        self._state.transition(running, RunStatus.WAITING_APPROVAL),
                        response.output,
                        approval.approval_id,
                    )
                self._budget.consume_tool_call()
                self._tools.execute(call, decision)
        except Exception as exc:
            failed = self._state.transition(
                running, RunStatus.FAILED, failure_code=type(exc).__name__
            )
            self._events.append_once(
                new_event(run.tenant_id, run.run_id, "run.failed", {"error": type(exc).__name__})
            )
            self._trajectory.append(run.tenant_id, run.run_id, "run.failed", type(exc).__name__)
            raise
        succeeded = self._state.transition(running, RunStatus.SUCCEEDED)
        self._events.append_once(
            new_event(run.tenant_id, run.run_id, "run.succeeded", {}, str(run.run_id))
        )
        self._trajectory.append(run.tenant_id, run.run_id, "run.succeeded", response.output)
        now = datetime.now(UTC)
        self._observability.emit_span(
            TraceSpan(uuid4(), run.tenant_id, run.run_id, "agent.run", now, now)
        )
        return GovernedRunResult(succeeded, response.output)
