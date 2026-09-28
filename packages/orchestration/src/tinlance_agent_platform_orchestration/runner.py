from dataclasses import dataclass
from typing import Callable
from uuid import UUID

from tinlance_agent_platform_contracts import Run, RunStatus, TaskSpec
from tinlance_agent_platform_runtime import RunStateMachine

@dataclass(frozen=True, slots=True)
class RunStep:
    run_id: UUID
    turn: int
    output: str

class AgentRunner:
    def __init__(self, model_call: Callable[[TaskSpec, int], str]) -> None:
        self._model_call = model_call
        self._state = RunStateMachine()

    def start(self, run: Run, task: TaskSpec) -> tuple[Run, RunStep]:
        if run.tenant_id != task.tenant_id or run.task_id != task.task_id:
            raise PermissionError("run and task tenant/identity mismatch")
        running = self._state.transition(run, RunStatus.RUNNING)
        next_run = self._state.next_turn(running)
        if next_run.turn_count > task.max_turns:
            return self._state.transition(next_run, RunStatus.FAILED, failure_code="turn_budget_exceeded"), RunStep(next_run.run_id, next_run.turn_count, "")
        try:
            output = self._model_call(task, next_run.turn_count)
        except Exception as exc:
            failed = self._state.transition(next_run, RunStatus.FAILED, failure_code=type(exc).__name__)
            return failed, RunStep(failed.run_id, failed.turn_count, "")
        return self._state.transition(next_run, RunStatus.SUCCEEDED), RunStep(next_run.run_id, next_run.turn_count, output)
