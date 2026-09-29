"""Intelligence / Research reference agent."""

from __future__ import annotations

from uuid import UUID

from tinlance_agent_platform_sdk import AgentPlatform, ToolDescriptor

from .base import ReferenceAgent, ToolPlan, WorkflowStep


class IntelligenceAgent(ReferenceAgent):
    name = "intelligence-research-agent"

    def __init__(self, client: AgentPlatform) -> None:
        super().__init__(client)
        for descriptor in (
            ToolDescriptor(
                "research.search",
                "research.search",
                "Collect public research through a governed source-access capability.",
            ),
            ToolDescriptor(
                "research.source",
                "research.source",
                "Retrieve a source for evidence interpretation.",
            ),
            ToolDescriptor(
                "research.report",
                "research.report",
                "Create an evidence-backed research report.",
            ),
            ToolDescriptor(
                "external.action",
                "external.action",
                "Perform an external consequential action; always approval-bound.",
            ),
        ):
            self.tools.register(descriptor)

    def workflow(self, objective: str) -> tuple[WorkflowStep, ...]:
        if not objective.strip():
            raise ValueError("objective is required")
        return (
            WorkflowStep("scope", "Define the intelligence question and target."),
            WorkflowStep("collect", "Collect source references through governed capabilities."),
            WorkflowStep("normalize", "Normalize sources and preserve provenance."),
            WorkflowStep("analyze", "Separate observations, evidence, analysis, and uncertainty."),
            WorkflowStep("report", "Produce an evidence-backed report."),
            WorkflowStep(
                "external_action",
                "Take a consequential external action only after Platform policy and approval.",
                consequential=True,
                requires_approval=True,
            ),
        )

    def plan_tools(self) -> tuple[ToolPlan, ...]:
        return (
            ToolPlan(self.tools.get("research.search"), "research.search", "public-web", "low", False),
            ToolPlan(self.tools.get("research.source"), "research.source", "source", "low", False),
            ToolPlan(self.tools.get("research.report"), "research.report", "report", "medium", False),
            ToolPlan(
                self.tools.get("external.action"),
                "external.action",
                "external-system",
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
