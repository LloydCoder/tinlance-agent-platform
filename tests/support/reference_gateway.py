"""Reference authority gateway for the executable Platform contract.

R10 consequential execution is delegated to the authoritative governed-execution
service; this gateway only translates the public HTTP envelope.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import RLock
from uuid import UUID, uuid4

from tinlance_agent_platform_agents import AgentRegistry
from tinlance_agent_platform_api.service import (
    APIHandler,
    APIRequest,
    APIResponse,
    AuthenticationError,
    ExecutionAPIError,
)
from tinlance_agent_platform_approvals import ApprovalService
from tinlance_agent_platform_contracts import (
    AgentDefinition,
    DataClass,
    Principal,
    Reversibility,
    RiskTier,
    Run,
    RunStatus,
    ToolCall,
)
from tinlance_agent_platform_events import EventStore, new_event
from tinlance_agent_platform_evidence import EvidenceStore
from tinlance_agent_platform_execution import (
    CONTRACT_VERSION,
    ExecutionErrorCode,
    ExecutionFailure,
    ExecutionRequest,
    ExecutionState,
    GovernedExecutionService,
)
from tinlance_agent_platform_runtime import RunStateMachine
from tinlance_agent_platform_tools import ToolGateway, ToolRegistration


@dataclass(frozen=True, slots=True)
class StaticPrincipalResolver:
    principals: dict[str, Principal]

    def resolve(self, bearer_token: str) -> Principal:
        principal = self.principals.get(bearer_token)
        if principal is None:
            raise AuthenticationError("authentication failed")
        return principal


class _ReferenceTool:
    def execute(self, call: ToolCall) -> str:
        return f"governed:{call.tool_name}:{call.action}:{call.resource}"


class ReferencePlatformGateway(APIHandler):
    def __init__(
        self,
        *,
        agents: AgentRegistry | None = None,
        approvals: ApprovalService | None = None,
        events: EventStore,
        evidence: EvidenceStore,
        approver_subjects: frozenset[str] = frozenset(),
        tools: ToolGateway | None = None,
    ) -> None:
        self.agents = agents or AgentRegistry()
        self.approvals = approvals or ApprovalService()
        self.events = events
        self.evidence = evidence
        self._runs: dict[UUID, Run] = {}
        self._lock = RLock()
        self._state = RunStateMachine()
        self.tools = tools or ToolGateway()
        if tools is None:
            self.tools.register(
                ToolRegistration(
                    name="reference.echo",
                    capability="repository.read",
                    description="Deterministic reference tool used by conformance tests.",
                    version="1",
                    risk=RiskTier.HIGH,
                    timeout_seconds=30.0,
                    max_tool_calls=1,
                    evidence_required=True,
                ),
                _ReferenceTool(),
            )
        self.approver_subjects = approver_subjects
        self.execution = GovernedExecutionService(
            agents=self.agents,
            approvals=self.approvals,
            tools=self.tools,
            events=self.events,
            evidence=self.evidence,
            platform_max_timeout_seconds=60.0,
        )

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
        if operation == "approvals.decide":
            return self._decide_approval(request)
        if operation == "tools.execute":
            return self._execute_tool(request)
        if operation == "executions.get":
            return self._execution_status(request)
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
            return self.agents.get(tenant_id, parsed, self.agents.latest_version(tenant_id, parsed))
        except (KeyError, ValueError) as exc:
            raise PermissionError("agent is not registered for tenant") from exc

    def _capabilities(self, request: APIRequest) -> APIResponse:
        agent = self._agent(request.tenant_id, self._required_text(request.payload, "agent_id"))
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
                request.tenant_id, parsed, "run.cancelled", {"request_id": request.request_id}
            )
        )
        return APIResponse(
            "accepted",
            {"run_id": run_id, "task_id": str(updated.task_id), "state": updated.status.value},
        )

    def _intent_fingerprint(self, request: APIRequest) -> str | None:
        raw = request.payload.get("execution_intent")
        if raw is None:
            return None
        if not isinstance(raw, dict):
            raise ValueError("execution_intent must be an object")
        risk = raw.get("risk", "low")
        reversibility = raw.get("reversibility", "reversible")
        data_class = raw.get("data_class", "internal")
        if not all(isinstance(value, str) for value in (risk, reversibility, data_class)):
            raise ValueError("execution intent classifications must be strings")
        intent = ExecutionRequest(
            request_id=request.request_id,
            idempotency_key=request.idempotency_key or request.request_id,
            tenant_id=request.tenant_id,
            principal_id=request.subject_id,
            agent_id=UUID(self._required_text(raw, "agent_id")),
            run_id=UUID(self._required_text(raw, "run_id")),
            capability_id=self._required_text(raw, "capability_id"),
            capability_version=self._required_text(raw, "capability_version"),
            tool_name=self._required_text(raw, "tool_name"),
            tool_version=self._required_text(raw, "tool_version"),
            action=self._required_text(raw, "action"),
            resource=self._required_text(raw, "resource"),
            input=raw.get("input") if isinstance(raw.get("input"), dict) else {},
            requested_timeout_seconds=float(raw.get("requested_timeout_seconds", 30.0)),
            requested_tool_calls=int(raw.get("requested_tool_calls", 1)),
            risk=RiskTier(risk),
            reversibility=Reversibility(reversibility),
            data_class=DataClass(data_class),
            blast_radius=str(raw.get("blast_radius", "single")),
            sandbox_required=bool(raw.get("sandbox_required", False)),
            evidence_required=bool(raw.get("evidence_required", True)),
            contract_version=str(raw.get("contract_version", CONTRACT_VERSION)),
        )
        return intent.fingerprint

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
            intent_fingerprint=self._intent_fingerprint(request)
            or (
                request.payload.get("intent_fingerprint")
                if isinstance(request.payload.get("intent_fingerprint"), str)
                else None
            ),
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

    def _decide_approval(self, request: APIRequest) -> APIResponse:
        approval_id = UUID(self._required_text(request.payload, "approval_id"))
        approved = request.payload.get("approved")
        if not isinstance(approved, bool):
            raise ValueError("approved must be boolean")
        if request.subject_id not in self.approver_subjects:
            raise PermissionError("authenticated principal is not an approval authority")
        item = self.approvals.decide(
            approval_id,
            approved,
            request.tenant_id,
            request.subject_id,
            intent_fingerprint=request.payload.get("intent_fingerprint")
            if isinstance(request.payload.get("intent_fingerprint"), str)
            else None,
        )
        self.events.append(
            new_event(
                request.tenant_id,
                item.run_id,
                "approval.decided",
                {
                    "approval_id": str(item.approval_id),
                    "request_id": request.request_id,
                    "decision": item.status.value,
                    "approver_subject_id": request.subject_id,
                },
            )
        )
        return APIResponse(
            "accepted", {"approval_id": str(item.approval_id), "state": item.status.value}
        )

    def _execute_tool(self, request: APIRequest) -> APIResponse:
        payload = request.payload
        approval_id = payload.get("approval_id")
        risk = payload.get("risk", "low")
        reversibility = payload.get("reversibility", "reversible")
        data_class = payload.get("data_class", "internal")
        if not all(isinstance(value, str) for value in (risk, reversibility, data_class)):
            raise ValueError("risk, reversibility and data_class must be strings")
        try:
            execution = self.execution.execute(
                self._principal(request),
                ExecutionRequest(
                    request_id=request.request_id,
                    idempotency_key=request.idempotency_key or request.request_id,
                    tenant_id=request.tenant_id,
                    principal_id=request.subject_id,
                    agent_id=UUID(self._required_text(payload, "agent_id")),
                    run_id=UUID(self._required_text(payload, "run_id")),
                    capability_id=self._required_text(payload, "capability_id"),
                    capability_version=self._required_text(payload, "capability_version"),
                    tool_name=self._required_text(payload, "tool_name"),
                    tool_version=self._required_text(payload, "tool_version"),
                    action=self._required_text(payload, "action"),
                    resource=self._required_text(payload, "resource"),
                    input=payload.get("input") if isinstance(payload.get("input"), dict) else {},
                    requested_timeout_seconds=float(payload.get("requested_timeout_seconds", 30.0)),
                    requested_tool_calls=int(payload.get("requested_tool_calls", 1)),
                    risk=RiskTier(risk),
                    reversibility=Reversibility(reversibility),
                    data_class=DataClass(data_class),
                    blast_radius=str(payload.get("blast_radius", "single")),
                    approval_id=UUID(approval_id) if isinstance(approval_id, str) else None,
                    sandbox_required=bool(payload.get("sandbox_required", False)),
                    evidence_required=bool(payload.get("evidence_required", True)),
                    contract_version=self._required_text(payload, "contract_version"),
                ),
                trace_id=request.trace_id,
            )
        except ExecutionFailure as exc:
            if exc.code is ExecutionErrorCode.APPROVAL_REQUIRED:
                return APIResponse("accepted", {"state": ExecutionState.WAITING_APPROVAL.value})
            if exc.code is ExecutionErrorCode.IDEMPOTENCY_CONFLICT:
                raise ExecutionAPIError(exc.code.value, str(exc), retryable=exc.retryable) from exc
            raise ExecutionAPIError(exc.code.value, str(exc), retryable=exc.retryable) from exc
        if execution.state is ExecutionState.COMPLETED:
            with self._lock:
                run = self._runs.get(UUID(self._required_text(payload, "run_id")))
                if run is not None and run.tenant_id == request.tenant_id:
                    running = self._state.transition(run, RunStatus.RUNNING)
                    self._runs[running.run_id] = self._state.transition(
                        running, RunStatus.SUCCEEDED
                    )
        return APIResponse(
            "accepted",
            {
                "execution_id": str(execution.execution_id),
                "state": execution.state.value,
                "output": execution.output,
                "evidence_ids": [str(item) for item in execution.evidence_ids],
                "audit_event_ids": [str(item) for item in execution.audit_event_ids],
                "error_code": execution.error_code.value if execution.error_code else None,
                "retryable": execution.retryable,
            },
        )

    def _execution_status(self, request: APIRequest) -> APIResponse:
        execution_id = UUID(self._required_text(request.payload, "execution_id"))
        try:
            result = self.execution.status(request.tenant_id, execution_id)
        except KeyError as exc:
            raise PermissionError("execution is not accessible") from exc
        return APIResponse(
            "ok",
            {
                "execution_id": str(result.execution_id),
                "state": result.state.value,
                "output": result.output,
                "evidence_ids": [str(item) for item in result.evidence_ids],
                "audit_event_ids": [str(item) for item in result.audit_event_ids],
                "error_code": result.error_code.value if result.error_code else None,
                "retryable": result.retryable,
            },
        )

    def _principal(self, request: APIRequest) -> Principal:
        value = request.authenticated_principal
        if isinstance(value, Principal):
            return value
        return Principal(request.subject_id, "user", request.tenant_id)

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
                        "request_id": item.payload.get("request_id", request.request_id),
                        "correlation_id": item.payload.get("request_id", request.request_id),
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
            "ok", {"evidence": [{"evidence_id": str(item.evidence_id)} for item in items]}
        )
