"""Authoritative governed consequential execution contract (R10).

The service is deliberately provider-neutral: identity resolution, durable persistence,
sandbox implementation, and external secret managers are injected at the boundary.
No caller can turn a client assertion into authority.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from threading import RLock
from time import monotonic
from typing import Any, Protocol
from uuid import UUID, uuid4

from tinlance_agent_platform_approvals import ApprovalService
from tinlance_agent_platform_contracts import (
    AgentDefinition,
    CapabilityRequest,
    DataClass,
    Decision,
    Principal,
    Reversibility,
    RiskTier,
)
from tinlance_agent_platform_events import EventStore, new_event
from tinlance_agent_platform_evidence import EvidenceStore
from tinlance_agent_platform_policy import evaluate
from tinlance_agent_platform_tools import (
    ToolCall,
    ToolGateway,
    ToolRegistration,
)


CONTRACT_VERSION = "governed-execution.v1"
MAX_INPUT_BYTES = 1 * 1024 * 1024


class ExecutionState(StrEnum):
    REQUESTED = "requested"
    WAITING_APPROVAL = "waiting_approval"
    AUTHORIZED = "authorized"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    DENIED = "denied"
    BUDGET_EXCEEDED = "budget_exceeded"
    OUTCOME_UNKNOWN = "outcome_unknown"


class ExecutionErrorCode(StrEnum):
    AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    TENANT_ACCESS_DENIED = "TENANT_ACCESS_DENIED"
    IDENTITY_BINDING_FAILED = "IDENTITY_BINDING_FAILED"
    POLICY_DENIED = "POLICY_DENIED"
    POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_BINDING_MISMATCH = "APPROVAL_BINDING_MISMATCH"
    APPROVAL_REPLAY = "APPROVAL_REPLAY"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    IDEMPOTENCY_UNAVAILABLE = "IDEMPOTENCY_UNAVAILABLE"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    SANDBOX_UNAVAILABLE = "SANDBOX_UNAVAILABLE"
    SECRET_ACCESS_DENIED = "SECRET_ACCESS_DENIED"
    CAPABILITY_NOT_FOUND = "CAPABILITY_NOT_FOUND"
    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"
    EVIDENCE_FAILURE = "EVIDENCE_FAILURE"
    AUDIT_FAILURE = "AUDIT_FAILURE"
    EXECUTION_OUTCOME_UNKNOWN = "EXECUTION_OUTCOME_UNKNOWN"
    INVALID_REQUEST = "INVALID_REQUEST"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ExecutionFailure(RuntimeError):
    def __init__(self, code: ExecutionErrorCode, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    request_id: str
    idempotency_key: str
    tenant_id: str
    principal_id: str
    agent_id: UUID
    run_id: UUID
    capability_id: str
    capability_version: str
    tool_name: str
    tool_version: str
    action: str
    resource: str
    input: dict[str, Any]
    requested_timeout_seconds: float
    requested_tool_calls: int = 1
    risk: RiskTier = RiskTier.LOW
    reversibility: Reversibility = Reversibility.REVERSIBLE
    data_class: DataClass = DataClass.INTERNAL
    blast_radius: str = "single"
    approval_id: UUID | None = None
    sandbox_required: bool = False
    evidence_required: bool = True

    def __post_init__(self) -> None:
        text_fields = (
            self.request_id, self.idempotency_key, self.tenant_id, self.principal_id,
            self.capability_id, self.capability_version, self.tool_name, self.tool_version,
            self.action, self.resource, self.blast_radius,
        )
        if any(not value or value != value.strip() for value in text_fields):
            raise ValueError("execution identity and scope fields must be normalized")
        if self.requested_timeout_seconds <= 0 or self.requested_tool_calls < 1:
            raise ValueError("execution limits must be positive")
        encoded = json.dumps(
            self.input, sort_keys=True, separators=(",", ":"), default=str
        ).encode()
        if len(encoded) > MAX_INPUT_BYTES:
            raise ValueError("execution input exceeds the maximum size")

    @property
    def fingerprint(self) -> str:
        canonical = json.dumps(
            {
                "contract_version": CONTRACT_VERSION,
                "tenant_id": self.tenant_id,
                "principal_id": self.principal_id,
                "agent_id": str(self.agent_id),
                "run_id": str(self.run_id),
                "capability_id": self.capability_id,
                "capability_version": self.capability_version,
                "tool_name": self.tool_name,
                "tool_version": self.tool_version,
                "action": self.action,
                "resource": self.resource,
                "input": self.input,
                "requested_timeout_seconds": self.requested_timeout_seconds,
                "requested_tool_calls": self.requested_tool_calls,
                "risk": self.risk.value,
                "reversibility": self.reversibility.value,
                "data_class": self.data_class.value,
                "blast_radius": self.blast_radius,
                "sandbox_required": self.sandbox_required,
                "evidence_required": self.evidence_required,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class ExecutionIdentity:
    execution_id: UUID
    tenant_id: str
    principal_id: str
    agent_id: UUID
    run_id: UUID
    capability_id: str
    tool_name: str
    policy_decision_id: str
    approval_id: UUID | None
    request_id: str
    trace_id: str | None


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    execution_id: UUID
    state: ExecutionState
    output: str | None
    evidence_ids: tuple[UUID, ...]
    audit_event_ids: tuple[UUID, ...]
    error_code: ExecutionErrorCode | None = None
    retryable: bool = False


@dataclass(frozen=True, slots=True)
class IdempotencyRecord:
    tenant_id: str
    key: str
    fingerprint: str
    execution_id: UUID
    result: ExecutionResult | None = None


class IdempotencyRepository(Protocol):
    def get(self, tenant_id: str, key: str) -> IdempotencyRecord | None: ...
    def claim(self, record: IdempotencyRecord) -> bool: ...
    def complete(self, record: IdempotencyRecord, result: ExecutionResult) -> None: ...


class InMemoryIdempotencyRepository:
    """Reference implementation; production must use a durable transactional store."""

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], IdempotencyRecord] = {}
        self._lock = RLock()

    def get(self, tenant_id: str, key: str) -> IdempotencyRecord | None:
        with self._lock:
            return self._items.get((tenant_id, key))

    def claim(self, record: IdempotencyRecord) -> bool:
        with self._lock:
            key = (record.tenant_id, record.key)
            if key in self._items:
                return False
            self._items[key] = record
            return True

    def complete(self, record: IdempotencyRecord, result: ExecutionResult) -> None:
        with self._lock:
            self._items[(record.tenant_id, record.key)] = IdempotencyRecord(
                record.tenant_id, record.key, record.fingerprint, record.execution_id, result
            )


class SandboxGate(Protocol):
    def establish(self, request: ExecutionRequest) -> None: ...


class SecretGate(Protocol):
    def authorize(self, request: ExecutionRequest) -> None: ...


class GovernedExecutionService:
    """Single authoritative consequential execution boundary."""

    def __init__(
        self,
        *,
        agents: Any,
        approvals: ApprovalService,
        tools: ToolGateway,
        events: EventStore,
        evidence: EvidenceStore,
        idempotency: IdempotencyRepository | None = None,
        sandbox: SandboxGate | None = None,
        secrets: SecretGate | None = None,
        platform_max_timeout_seconds: float = 300.0,
    ) -> None:
        self.agents = agents
        self.approvals = approvals
        self.tools = tools
        self.events = events
        self.evidence = evidence
        self.idempotency = idempotency or InMemoryIdempotencyRepository()
        self.sandbox = sandbox
        self.secrets = secrets
        self.platform_max_timeout_seconds = platform_max_timeout_seconds
        self._lock = RLock()
        self._identities: dict[UUID, ExecutionIdentity] = {}
        self._states: dict[UUID, ExecutionState] = {}
        self._results: dict[UUID, ExecutionResult] = {}

    def execute(
        self,
        principal: Principal,
        request: ExecutionRequest,
        *,
        trace_id: str | None = None,
    ) -> ExecutionResult:
        self._bind_principal(principal, request)
        existing = self.idempotency.get(request.tenant_id, request.idempotency_key)
        if existing is not None:
            if existing.fingerprint != request.fingerprint:
                raise ExecutionFailure(
                    ExecutionErrorCode.IDEMPOTENCY_CONFLICT,
                    "idempotency key conflicts with a different execution",
                )
            if existing.result is not None:
                return existing.result
            execution_id = existing.execution_id
            record = existing
        else:
            execution_id = uuid4()
            record = IdempotencyRecord(
                request.tenant_id, request.idempotency_key, request.fingerprint, execution_id
            )
            if not self.idempotency.claim(record):
                return self.execute(principal, request, trace_id=trace_id)

        identity = ExecutionIdentity(
            execution_id, request.tenant_id, request.principal_id, request.agent_id,
            request.run_id, request.capability_id, request.tool_name, "", request.approval_id,
            request.request_id, trace_id,
        )
        self._states[execution_id] = ExecutionState.REQUESTED
        audit_ids: list[UUID] = []
        try:
            self._event(request, execution_id, "execution.requested", audit_ids)
            agent = self._agent(request)
            self._bind_agent(principal, request, agent)
            registration = self._tool(request)
            self._authorize_capability(agent, principal, request, registration)
            if request.requested_tool_calls > registration.max_tool_calls:
                raise ExecutionFailure(
                    ExecutionErrorCode.BUDGET_EXCEEDED,
                    "requested tool-call budget exceeds the registered tool limit",
                )
            if registration.risk is not None:
                risk_order = {
                    RiskTier.LOW: 0,
                    RiskTier.MEDIUM: 1,
                    RiskTier.HIGH: 2,
                    RiskTier.CRITICAL: 3,
                    RiskTier.PROHIBITED: 4,
                }
                if risk_order[request.risk] > risk_order[registration.risk]:
                    raise ExecutionFailure(
                        ExecutionErrorCode.AUTHORIZATION_DENIED,
                        "requested risk exceeds the registered tool risk ceiling",
                    )
            policy = evaluate(CapabilityRequest(
                request.action, request.resource, frozenset({request.capability_id}),
                request.risk, request.reversibility, request.data_class,
                request.blast_radius, request.input,
            ))
            if policy.decision is Decision.DENY:
                self._deny(execution_id, request, ExecutionErrorCode.POLICY_DENIED, audit_ids)
            policy_id = f"{policy.policy_id}:{policy.policy_version}"
            identity = ExecutionIdentity(
                execution_id, request.tenant_id, request.principal_id, request.agent_id,
                request.capability_id, request.tool_name, policy_id, request.approval_id,
                request.request_id, trace_id,
            )
            self._identities[execution_id] = identity
            self._event(request, execution_id, "execution.identity_bound", audit_ids)
            self._event(request, execution_id, "execution.policy_evaluated", audit_ids)
            if policy.requires_approval:
                if request.approval_id is None:
                    self._states[execution_id] = ExecutionState.WAITING_APPROVAL
                    self._event(request, execution_id, "execution.approval_required", audit_ids)
                    raise ExecutionFailure(
                        ExecutionErrorCode.APPROVAL_REQUIRED, "approval is required"
                    )
            elif request.approval_id is not None:
                self.approvals.require_approved(request.approval_id)
            self._event(request, execution_id, "execution.budget_reserved", audit_ids)
            effective_timeout = min(
                request.requested_timeout_seconds,
                registration.timeout_seconds,
                self.platform_max_timeout_seconds,
            )
            if effective_timeout <= 0:
                raise ExecutionFailure(ExecutionErrorCode.TIMEOUT, "effective timeout is invalid")
            if request.sandbox_required or registration.sandbox_required:
                if self.sandbox is None:
                    raise ExecutionFailure(
                        ExecutionErrorCode.SANDBOX_UNAVAILABLE,
                        "required sandbox is unavailable",
                    )
                self.sandbox.establish(request)
                self._event(request, execution_id, "execution.sandbox_started", audit_ids)
            if self.secrets is not None:
                self.secrets.authorize(request)
            self._states[execution_id] = ExecutionState.AUTHORIZED
            self._event(request, execution_id, "execution.started", audit_ids)
            started = monotonic()
            call = ToolCall(
                uuid4(), request.tenant_id, request.run_id, request.tool_name,
                request.capability_id, request.action, request.resource,
            )
            output = self.tools.execute(call, policy, request.approval_id, self.approvals)
            if request.approval_id is not None:
                self._event(request, execution_id, "approval.consumed", audit_ids)
            if monotonic() - started > effective_timeout:
                self._states[execution_id] = ExecutionState.OUTCOME_UNKNOWN
                self._event(request, execution_id, "execution.timed_out", audit_ids)
                result = ExecutionResult(
                    execution_id, ExecutionState.OUTCOME_UNKNOWN, None, (), tuple(audit_ids),
                    ExecutionErrorCode.EXECUTION_OUTCOME_UNKNOWN, False,
                )
                self.idempotency.complete(record, result)
                self._results[execution_id] = result
                return result
            evidence_ids: list[UUID] = []
            if request.evidence_required:
                try:
                    item = self.evidence.append(
                        request.tenant_id, request.run_id, output, execution_id
                    )
                    evidence_ids.append(item.evidence_id)
                    self._event(request, execution_id, "execution.evidence_committed", audit_ids)
                except Exception as exc:
                    self._states[execution_id] = ExecutionState.FAILED
                    self._event(request, execution_id, "execution.failed", audit_ids)
                    raise ExecutionFailure(
                        ExecutionErrorCode.EVIDENCE_FAILURE,
                        "mandatory evidence could not be committed",
                    ) from exc
            self._states[execution_id] = ExecutionState.COMPLETED
            self._event(request, execution_id, "execution.completed", audit_ids)
            self._event(request, execution_id, "execution.finalized", audit_ids)
            result = ExecutionResult(
                execution_id,
                ExecutionState.COMPLETED,
                output,
                tuple(evidence_ids),
                tuple(audit_ids),
            )
            self.idempotency.complete(record, result)
            self._results[execution_id] = result
            return result
        except ExecutionFailure as exc:
            state = {
                ExecutionErrorCode.APPROVAL_REQUIRED: ExecutionState.WAITING_APPROVAL,
                ExecutionErrorCode.BUDGET_EXCEEDED: ExecutionState.BUDGET_EXCEEDED,
                ExecutionErrorCode.TIMEOUT: ExecutionState.TIMED_OUT,
                ExecutionErrorCode.CANCELLED: ExecutionState.CANCELLED,
                ExecutionErrorCode.EXECUTION_OUTCOME_UNKNOWN: ExecutionState.OUTCOME_UNKNOWN,
                ExecutionErrorCode.POLICY_DENIED: ExecutionState.DENIED,
            }.get(exc.code, ExecutionState.FAILED)
            self._states[execution_id] = state
            if state is not ExecutionState.WAITING_APPROVAL:
                self._event(request, execution_id, "execution.failed", audit_ids)
                result = ExecutionResult(
                    execution_id, state, None, (), tuple(audit_ids), exc.code, exc.retryable
                )
                self.idempotency.complete(record, result)
                self._results[execution_id] = result
            raise
        except Exception as exc:
            self._states[execution_id] = ExecutionState.OUTCOME_UNKNOWN
            from contextlib import suppress
            with suppress(Exception):
                self._event(request, execution_id, "execution.failed", audit_ids)
            result = ExecutionResult(
                execution_id, ExecutionState.OUTCOME_UNKNOWN, None, (), tuple(audit_ids),
                ExecutionErrorCode.EXECUTION_OUTCOME_UNKNOWN, False,
            )
            self.idempotency.complete(record, result)
            self._results[execution_id] = result
            raise ExecutionFailure(
                ExecutionErrorCode.EXECUTION_OUTCOME_UNKNOWN,
                "execution outcome could not be established",
            ) from exc

    def status(self, tenant_id: str, execution_id: UUID) -> ExecutionResult:
        if not tenant_id or tenant_id != tenant_id.strip():
            raise ValueError("tenant identifier must be normalized")
        result = self._results.get(execution_id)
        identity = self._identities.get(execution_id)
        if identity is None or identity.tenant_id != tenant_id:
            raise PermissionError("execution is not owned by tenant")
        if result is not None:
            return result
        state = self._states.get(execution_id)
        if state is None:
            raise KeyError("execution does not exist")
        return ExecutionResult(execution_id, state, None, (), ())

    def _bind_principal(self, principal: Principal, request: ExecutionRequest) -> None:
        if principal.tenant_id != request.tenant_id or principal.subject_id != request.principal_id:
            raise ExecutionFailure(
                ExecutionErrorCode.IDENTITY_BINDING_FAILED,
                "authenticated principal does not match execution identity",
            )

    def _agent(self, request: ExecutionRequest) -> AgentDefinition:
        try:
            version = self.agents.latest_version(request.tenant_id, request.agent_id)
            return self.agents.get(request.tenant_id, request.agent_id, version)
        except (KeyError, ValueError) as exc:
            raise ExecutionFailure(
                ExecutionErrorCode.IDENTITY_BINDING_FAILED,
                "agent is not registered for the tenant",
            ) from exc

    @staticmethod
    def _bind_agent(
        principal: Principal, request: ExecutionRequest, agent: AgentDefinition
    ) -> None:
        if agent.tenant_id != request.tenant_id or agent.owner_subject_id != principal.subject_id:
            raise ExecutionFailure(
                ExecutionErrorCode.IDENTITY_BINDING_FAILED,
                "agent is not bound to the authenticated principal",
            )

    def _tool(self, request: ExecutionRequest) -> ToolRegistration:
        try:
            registration = self.tools.registration(request.tool_name)
        except KeyError as exc:
            raise ExecutionFailure(
                ExecutionErrorCode.TOOL_NOT_FOUND, "tool is not registered"
            ) from exc
        if (
            registration.capability != request.capability_id
            or registration.version != request.tool_version
        ):
            raise ExecutionFailure(
                ExecutionErrorCode.CAPABILITY_NOT_FOUND,
                "tool capability/version binding failed",
            )
        return registration

    @staticmethod
    def _authorize_capability(
        agent: AgentDefinition,
        principal: Principal,
        request: ExecutionRequest,
        registration: ToolRegistration,
    ) -> None:
        if request.capability_id not in agent.capabilities:
            raise ExecutionFailure(
                ExecutionErrorCode.AUTHORIZATION_DENIED,
                "agent lacks requested capability",
            )
        if principal.scopes and request.capability_id not in principal.scopes:
            raise ExecutionFailure(
                ExecutionErrorCode.AUTHORIZATION_DENIED,
                "principal lacks requested capability scope",
            )
        if registration.risk.value == "prohibited":
            raise ExecutionFailure(
                ExecutionErrorCode.AUTHORIZATION_DENIED,
                "prohibited capability cannot execute",
            )

    def _deny(
        self,
        execution_id: UUID,
        request: ExecutionRequest,
        code: ExecutionErrorCode,
        audit_ids: list[UUID],
    ) -> None:
        self._states[execution_id] = ExecutionState.DENIED
        self._event(request, execution_id, "authorization.denied", audit_ids)
        raise ExecutionFailure(code, "execution denied")

    def _event(
        self,
        request: ExecutionRequest,
        execution_id: UUID,
        event_type: str,
        audit_ids: list[UUID],
    ) -> None:
        event = new_event(
            request.tenant_id,
            request.run_id,
            event_type,
            {
                "request_id": request.request_id,
                "principal_id": request.principal_id,
                "agent_id": str(request.agent_id),
                "capability_id": request.capability_id,
                "tool_name": request.tool_name,
                "execution_id": str(execution_id),
            },
        )
        stored = self.events.append(event)
        audit_ids.append(stored.event_id)
