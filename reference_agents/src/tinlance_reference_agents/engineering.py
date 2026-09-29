"""Software Engineering reference agent."""

from __future__ import annotations

from uuid import UUID

from tinlance_agent_platform_sdk import AgentPlatform, ToolDescriptor

from .base import AgentRun, ReferenceAgent, ToolPlan, WorkflowStep


class EngineeringAgent(ReferenceAgent):
    name = "software-engineering-agent"

    def __init__(self, client: AgentPlatform) -> None:
        super().__init__(client)
        for descriptor in (
            ToolDescriptor(
                "repository.read",
                "repository.read",
                "Inspect source, configuration, and repository metadata.",
            ),
            ToolDescriptor(
                "ci.inspect",
                "ci.inspect",
                "Inspect test and CI results without modifying repository state.",
            ),
            ToolDescriptor(
                "repository.write",
                "repository.write",
                "Apply a code change; requires governed authorization.",
            ),
            ToolDescriptor(
                "pull_request.merge",
                "pull_request.merge",
                "Merge a pull request; requires governed authorization.",
            ),
            ToolDescriptor(
                "deployment.trigger",
                "deployment.trigger",
                "Trigger deployment; requires governed authorization.",
            ),
        ):
            self.tools.register(descriptor)

    def workflow(self, objective: str) -> tuple[WorkflowStep, ...]:
        if not objective.strip():
            raise ValueError("objective is required")
        return (
            WorkflowStep("intake", "Normalize the engineering objective and scope."),
            WorkflowStep("inspect", "Inspect code, configuration, issues, and CI evidence."),
            WorkflowStep("diagnose", "Analyze failures and separate evidence from hypotheses."),
            WorkflowStep("propose", "Prepare a patch plan and verification plan."),
            WorkflowStep(
                "write",
                "Modify repository state only after the Platform approval boundary.",
                consequential=True,
                requires_approval=True,
            ),
            WorkflowStep(
                "merge",
                "Merge a reviewed change only after explicit Platform authorization.",
                consequential=True,
                requires_approval=True,
            ),
            WorkflowStep(
                "deploy",
                "Trigger deployment only through a governed Platform capability.",
                consequential=True,
                requires_approval=True,
            ),
        )

    def plan_tools(self) -> tuple[ToolPlan, ...]:
        return (
            ToolPlan(
                self.tools.get("repository.read"),
                "repository.read",
                "repository",
                "low",
                False,
            ),
            ToolPlan(
                self.tools.get("ci.inspect"),
                "ci.inspect",
                "ci",
                "low",
                False,
            ),
            ToolPlan(
                self.tools.get("repository.write"),
                "repository.write",
                "repository",
                "high",
                True,
            ),
            ToolPlan(
                self.tools.get("pull_request.merge"),
                "pull_request.merge",
                "pull_request",
                "high",
                True,
            ),
            ToolPlan(
                self.tools.get("deployment.trigger"),
                "deployment.trigger",
                "environment",
                "critical",
                True,
            ),
        )

    def start_task(
        self,
        *,
        task_id: UUID | str,
        agent_id: UUID | str,
        objective: str,
        request_id: str | None = None,
    ) -> AgentRun:
        return self.start(
            task_id=task_id,
            agent_id=agent_id,
            objective=objective,
            workflow=self.workflow(objective),
            planned_tools=self.plan_tools(),
            request_id=request_id,
        )
