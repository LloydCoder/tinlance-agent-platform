from dataclasses import replace

from tinlance_agent_platform_contracts import Run, RunStatus


class InvalidTransition(ValueError):
    pass


_ALLOWED = {
    RunStatus.CREATED: frozenset({RunStatus.RUNNING, RunStatus.CANCELLED}),
    RunStatus.RUNNING: frozenset(
        {
            RunStatus.WAITING_APPROVAL,
            RunStatus.SUCCEEDED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
        }
    ),
    RunStatus.WAITING_APPROVAL: frozenset(
        {RunStatus.RUNNING, RunStatus.FAILED, RunStatus.CANCELLED}
    ),
    RunStatus.SUCCEEDED: frozenset(),
    RunStatus.FAILED: frozenset(),
    RunStatus.CANCELLED: frozenset(),
}


class RunStateMachine:
    def transition(
        self,
        run: Run,
        target: RunStatus,
        *,
        failure_code: str | None = None,
    ) -> Run:
        if target not in _ALLOWED[run.status]:
            raise InvalidTransition(f"{run.status} -> {target} is forbidden")
        return replace(run, status=target, failure_code=failure_code)

    def next_turn(self, run: Run) -> Run:
        if run.status is not RunStatus.RUNNING:
            raise InvalidTransition("only running runs can consume a turn")
        return replace(run, turn_count=run.turn_count + 1)
