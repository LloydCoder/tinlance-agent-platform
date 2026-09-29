"""Reference authority-preserving gateway for the Agent OS integration contract.

The gateway is intentionally transport-neutral. Authentication is resolved before
this layer by an injected PrincipalResolver; request tenant/subject fields are
checked against the authenticated principal rather than trusted as authority.
Production deployments should replace the resolver and in-memory stores with
durable implementations.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import RLock
from uuid import UUID, uuid4

from tinlance_agent_platform_agents import AgentRegistry
from tinlance_agent_platform_approvals import ApprovalService
from tinlance_agent_platform_contracts import (
    AgentDefinition,
    Principal,
    Run,
    RunStatus,
)
from tinlance_agent_platform_events import EventStore, new_event
from tinlance_agent_platform_evidence import EvidenceStore
from tinlance_agent_platform_runtime import RunStateMachine

from tinlance_agent_platform_api.service import (
    APIHandler,
    APIRequest,
    APIResponse,
    AuthenticationError,
)


@dataclass(frozen=True, slots=True)
class StaticPrincipalResolver:
    """Deterministic resolver for local tests and development only."""

    principals: dict[str, Principal]

    def resolve(self, bearer_token: str) -> Principal:
        principal = self.principals.get(bearer_token)
        if principal is None:
            raise AuthenticationError("authentication failed")
        return principal


class ReferencePlatformGateway(APIHandler):
    """Executable reference gateway used by the HTTP boundary and conformance tests."""

    def __init__(
        self,
        *,
        agents: AgentRegistry | None = None,
        approvals: ApprovalService | None = None,
        events: EventStore,
        evidence: EvidenceStore,
    ) -> None:
        self.agents = agents or AgentRegistry()
        self.approvals = approvals or ApprovalService()
        self.events = events
        self.evidence = evidence
        self._runs: dict[UUID, Run] = {}
        self._lock = RLock()
        self._state = RunStateMachine()

    def register_agent(self, agent: AgentDefinition) -> AgentDefinition:
        return self.agents.register(agent)

    def handle(self, request: APIRequest) -> APIResponse:
        operation = request.operation
        if operation == "health":
            return APIResponse("ok", {"ready": True})
        if operation == "principal.get":
            return APIResponse("ok", {"user_id": request.subject_id})
        if operation == "agents.list":
            items = self.agents.list_for_tenant(request.tenant_id)
            return APIResponse(
                "ok",
                {
                    "agents": [
                        {
                            "agent_id": str(agent.agent_id),
                            "name": agent.name,
                            "version": agent.version,
                        }
                        for agent in items
                    ]
                },
            )
        if operation == "capabilities.list":
            return self._capabilities(request)
        if operation == "runs.create":
            return self._create_run(request)
        if operation == "runs.cancel":
            return self._cancel_run(request)
        if operation == "approvals.request":
            return self._request_approval(request)
        if operation == "runs.events":
            return self._events(request)
        if operation == "runs.evidence":
            return self._evidence(request)
        raise ValueError("unsupported Platform operation")

    @staticmethod
    def _required_text(payload: dict[str, object], key: str) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} is required")
        return value

    def _agent(self, tenant_id: str, agent_id: str) -> AgentDefinition:
        try:
            parsed = UUID(agent_id)
        except ValueError as exc:
            raise ValueError("agent_id must be a UUID") from exc
        return self.agents.get(tenant_id, parsed, self.agents.latest_version(tenant_id, parsed))

    def _capabilities(self, request: APIRequest) -> APIResponse:
        agent = self._agent(
            request.tenant_id,
            self._required_text(request.payload, "agent_id"),
        )
        return APIResponse(
            "ok",
            {
                "capabilities": [
                    {"capability_id": capability} for capability in sorted(agent.capabilities)
                ]
            },
        )

    def _create_run(self, request: APIRequest) -> APIResponse:
        task_id = self._required_text(request.payload, "task_id")
        agent_id = self._required_text(request.payload, "agent_id")
        self._required_text(request.payload, "intent")
        agent = self._agent(request.tenant_id, agent_id)
        if agent.owner_subject_id != request.subject_id:
            raise PermissionError("requester is not the registered agent owner")
        parsed_task = UUID(task_id)
        parsed_agent = UUID(agent_id)
        run = Run(uuid4(), parsed_task, request.tenant_id)
        with self._lock:
            self._runs[run.run_id] = self._state.transition(run, RunStatus.RUNNING)
        self.events.append(
            new_event(
                request.tenant_id,
                run.run_id,
                "run.created",
                {"task_id": task_id, "agent_id": agent_id, "request_id": request.request_id},
            )
        )
        return APIResponse(
            "accepted",
            {
                "run_id": str(run.run_id),
                "task_id": str(parsed_task),
                "state": RunStatus.RUNNING.value,
                "agent_id": str(parsed_agent),
            },
        )

    def _cancel_run(self, request: APIRequest) -> APIResponse:
        run_id = self._required_text(request.payload, "run_id")
        parsed = UUID(run_id)
        with self._lock:
            run = self._runs.get(parsed)
            if run is None or run.tenant_id != request.tenant_id:
                raise PermissionError("run is not owned by tenant")
            updated = self._state.transition(run, RunStatus.CANCELLED)
            self._runs[parsed] = updated
        self.events.append(
            new_event(
                request.tenant_id,
                parsed,
                "run.cancelled",
                {"request_id": request.request_id},
            )
        )
        return APIResponse(
            "accepted",
            {"run_id": run_id, "task_id": str(updated.task_id), "state": updated.status.value},
        )

    def _request_approval(self, request: APIRequest) -> APIResponse:
        run_id = self._required_text(request.payload, "run_id")
        action = self._required_text(request.payload, "action")
        resource = self._required_text(request.payload, "resource")
        reason = self._required_text(request.payload, "reason")
        parsed = UUID(run_id)
        with self._lock:
            run = self._runs.get(parsed)
            if run is None or run.tenant_id != request.tenant_id:
                raise PermissionError("run is not owned by tenant")
        approval = self.approvals.request(
            request.tenant_id,
            parsed,
            action,
            resource,
            reason,
            request.subject_id,
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
        with self._lock:
            self._runs[parsed] = self._state.transition(run, RunStatus.WAITING_APPROVAL)
        self.events.append(
            new_event(
                request.tenant_id,
                parsed,
                "approval.requested",
                {"approval_id": str(approval.approval_id), "request_id": request.request_id},
            )
        )
        return APIResponse("accepted", {"approval_id": str(approval.approval_id)})

    def _events(self, request: APIRequest) -> APIResponse:
        run_id = request.payload.get("run_id")
        if not isinstance(run_id, str):
            raise ValueError("run_id is required")
        parsed = UUID(run_id)
        items = self.events.list_for_run(request.tenant_id, parsed)
        return APIResponse(
            "ok",
            {
                "events": [
                    {
                        "event_id": str(item.event_id),
                        "event_type": item.event_type,
                        "occurred_at": item.occurred_at.isoformat(),
                        "request_id": request.request_id,
                        "correlation_id": request.request_id,
                        "workspace_id": request.tenant_id,
                        "task_id": None,
                        "agent_id": None,
                        "platform_run_id": str(item.run_id),
                        "payload": dict(item.payload),
                    }
                    for item in items
                ]
            },
        )

    def _evidence(self, request: APIRequest) -> APIResponse:
        run_id = request.payload.get("run_id")
        if not isinstance(run_id, str):
            raise ValueError("run_id is required")
        parsed = UUID(run_id)
        items = self.evidence.list_for_run(request.tenant_id, parsed)
        return APIResponse(
            "ok",
            {"evidence": [{"evidence_id": str(item.evidence_id)} for item in items]},
        )
