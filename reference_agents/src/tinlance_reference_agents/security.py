"""Security Research reference agent."""

from __future__ import annotations

from uuid import UUID

from tinlance_agent_platform_sdk import AgentPlatform, ToolDescriptor

from .base import ReferenceAgent, ToolPlan, WorkflowStep


class SecurityResearchAgent(ReferenceAgent):
    name = "security-research-agent"

    def __init__(self, client: AgentPlatform) -> None:
        super().__init__(client)
        self.tools.register(
            ToolDescriptor(
                name="repository.read",
                capability="repository.read",
                description="Read repository content through a Platform-governed capability.",
            )
        )
        self.tools.register(
            ToolDescriptor(
                name="security.scan",
                capability="security.scan",
                description="Run an approved security-analysis capability through the Platform.",
            )
        )
        self.tools.register(
            ToolDescriptor(
                name="repository.write",
                capability="repository.write",
                description="Modify repository state; always treated as consequential.",
            )
        )

    def workflow(self, objective: str) -> tuple[WorkflowStep, ...]:
        if not objective.strip():
            raise ValueError("objective is required")
        return (
            WorkflowStep("scope", "Establish the requested security-research objective."),
            WorkflowStep(
                "inspect",
                "Inspect repository evidence through governed read capabilities.",
            ),
            WorkflowStep(
                "analyze",
                "Interpret observations without promoting model output to evidence.",
            ),
            WorkflowStep("synthesize", "Produce findings only where evidence supports the claim."),
            WorkflowStep(
                "remediate",
                "Prepare a remediation proposal; no mutation is performed here.",
            ),
            WorkflowStep(
                "modify",
                "Apply a repository change only after Platform policy and human approval.",
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
                self.tools.get("security.scan"),
                "security.scan",
                "repository",
                "medium",
                False,
            ),
            ToolPlan(
                self.tools.get("repository.write"),
                "repository.write",
                "repository",
                "high",
                True,
            ),
        )

    def start_research(
        self,
        *,
        task_id: UUID | str,
        agent_id: UUID | str,
        objective: str,
        request_id: str | None = None,
    ):
        return self.start(
            task_id=task_id,
            agent_id=agent_id,
            objective=objective,
            workflow=self.workflow(objective),
            planned_tools=self.plan_tools(),
            request_id=request_id,
        )
