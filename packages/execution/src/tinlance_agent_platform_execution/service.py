"""Authoritative governed consequential execution contract (R10).

The service is deliberately provider-neutral: identity resolution, durable persistence,
sandbox implementation, and external secret managers are injected at the boundary.
No caller can turn a client assertion into authority.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from threading import RLock
from time import monotonic
from typing import Any, Protocol, cast
from uuid import UUID, uuid4

from tinlance_agent_platform_approvals import ApprovalService
from tinlance_agent_platform_budgets import BudgetScope
from tinlance_agent_platform_contracts import (
    AgentDefinition,
    ApprovalStatus,
    CapabilityRequest,
    DataClass,
    Decision,
    Principal,
    RequestContext,
    Reversibility,
    RiskTier,
)
from tinlance_agent_platform_events import EventStore, new_event
from tinlance_agent_platform_evidence import EvidenceStore
from tinlance_agent_platform_policy import evaluate
from tinlance_agent_platform_tools import ToolCall, ToolGateway, ToolRegistration

from .journal import ExecutionJournal, JournalRecord, JournalState, encode_result

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
    ADDITIONAL_AUTHORIZATION_REQUIRED = "ADDITIONAL_AUTHORIZATION_REQUIRED"
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
    def __init__(
        self,
        code: ExecutionErrorCode,
        message: str,
        *,
        retryable: bool = False,
        execution_id: UUID | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable
        self.execution_id = execution_id


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
    contract_version: str = CONTRACT_VERSION

    def __post_init__(self) -> None:
        text_fields = (
            self.request_id,
            self.idempotency_key,
            self.tenant_id,
            self.principal_id,
            self.capability_id,
            self.capability_version,
            self.tool_name,
            self.tool_version,
            self.action,
            self.resource,
            self.blast_radius,
        )
        if self.contract_version != CONTRACT_VERSION:
            raise ValueError("unsupported governed execution contract version")
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

    def redact_output(self, request: ExecutionRequest, output: str) -> str: ...


class BudgetGate(Protocol):
    def reserve_scoped(
        self,
        scope: BudgetScope,
        *,
        tool_calls: int,
        seconds: float,
    ) -> Any: ...

    def consume(self, reservation: Any, elapsed_seconds: float) -> None: ...

    def release(self, reservation: Any) -> None: ...


class SQLiteIdempotencyRepository:
    """Durable single-host idempotency store using SQLite transactions."""

    def __init__(self, path: str) -> None:
        if not path.strip():
            raise ValueError("idempotency database path is required")
        self.path = path
        with sqlite3.connect(self.path, timeout=10.0) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA busy_timeout=10000")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS governed_execution_idempotency (
                    tenant_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    execution_id TEXT NOT NULL,
                    result_json TEXT,
                    PRIMARY KEY (tenant_id, idempotency_key)
                )
                """
            )
            connection.commit()

    @staticmethod
    def _decode(row: tuple[object, ...]) -> IdempotencyRecord:
        tenant_id, key, fingerprint, execution_id, result_json = row
        result = None
        if isinstance(result_json, str):
            payload = json.loads(result_json)
            result = ExecutionResult(
                UUID(payload["execution_id"]),
                ExecutionState(payload["state"]),
                payload.get("output"),
                tuple(UUID(item) for item in payload.get("evidence_ids", [])),
                tuple(UUID(item) for item in payload.get("audit_event_ids", [])),
                ExecutionErrorCode(payload["error_code"]) if payload.get("error_code") else None,
                bool(payload.get("retryable", False)),
            )
        return IdempotencyRecord(
            str(tenant_id),
            str(key),
            str(fingerprint),
            UUID(str(execution_id)),
            result,
        )

    def get(self, tenant_id: str, key: str) -> IdempotencyRecord | None:
        with sqlite3.connect(self.path, timeout=10.0) as connection:
            row = connection.execute(
                "SELECT tenant_id, idempotency_key, fingerprint, execution_id, result_json "
                "FROM governed_execution_idempotency WHERE tenant_id = ? AND idempotency_key = ?",
                (tenant_id, key),
            ).fetchone()
        return self._decode(row) if row is not None else None

    def claim(self, record: IdempotencyRecord) -> bool:
        with sqlite3.connect(self.path, timeout=10.0) as connection:
            connection.execute("PRAGMA busy_timeout=10000")
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "INSERT OR IGNORE INTO governed_execution_idempotency "
                "(tenant_id, idempotency_key, fingerprint, execution_id) VALUES (?, ?, ?, ?)",
                (
                    record.tenant_id,
                    record.key,
                    record.fingerprint,
                    str(record.execution_id),
                ),
            )
            connection.commit()
        return cursor.rowcount == 1

    def complete(self, record: IdempotencyRecord, result: ExecutionResult) -> None:
        payload = json.dumps(
            {
                "execution_id": str(result.execution_id),
                "state": result.state.value,
                "output": result.output,
                "evidence_ids": [str(item) for item in result.evidence_ids],
                "audit_event_ids": [str(item) for item in result.audit_event_ids],
                "error_code": result.error_code.value if result.error_code else None,
                "retryable": result.retryable,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        with sqlite3.connect(self.path, timeout=10.0) as connection:
            connection.execute("PRAGMA busy_timeout=10000")
            connection.execute(
                "UPDATE governed_execution_idempotency SET result_json = ? "
                "WHERE tenant_id = ? AND idempotency_key = ? AND fingerprint = ?",
                (payload, record.tenant_id, record.key, record.fingerprint),
            )
            connection.commit()


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
        journal: ExecutionJournal | None = None,
        sandbox: SandboxGate | None = None,
        secrets: SecretGate | None = None,
        budget: BudgetGate | None = None,
        platform_max_timeout_seconds: float = 300.0,
    ) -> None:
        self.agents = agents
        self.approvals = approvals
        self.tools = tools
        self.events = events
        self.evidence = evidence
        self.idempotency = idempotency or InMemoryIdempotencyRepository()
        self.journal = journal
        self.sandbox = sandbox
        self.secrets = secrets
        self.budget = budget
        self.platform_max_timeout_seconds = platform_max_timeout_seconds
        self._lock = RLock()
        self._identities: dict[UUID, ExecutionIdentity] = {}
        self._states: dict[UUID, ExecutionState] = {}
        self._results: dict[UUID, ExecutionResult] = {}
        self._trace_ids: dict[UUID, str | None] = {}
        self._execution_locks: dict[tuple[str, str], RLock] = {}

    def execute(
        self,
        principal: Principal,
        request: ExecutionRequest,
        *,
        trace_id: str | None = None,
    ) -> ExecutionResult:
        key = (request.tenant_id, request.idempotency_key)
        with self._lock:
            execution_lock = self._execution_locks.setdefault(key, RLock())
        with execution_lock:
            return self._execute_once(principal, request, trace_id=trace_id)

    def _execute_once(
        self,
        principal: Principal,
        request: ExecutionRequest,
        *,
        trace_id: str | None = None,
    ) -> ExecutionResult:
        self._bind_principal(principal, request)
        journal_record = (
            self.journal.get_by_idempotency(request.tenant_id, request.idempotency_key)
            if self.journal is not None
            else None
        )
        if journal_record is not None:
            if journal_record.fingerprint != request.fingerprint:
                raise ExecutionFailure(
                    ExecutionErrorCode.IDEMPOTENCY_CONFLICT,
                    "idempotency key conflicts with a different execution",
                )
            if journal_record.state is JournalState.COMPLETED and journal_record.result_json:
                return self._decode_result(journal_record.result_json)
            if (
                journal_record.side_effect_started
                or journal_record.state is JournalState.OUTCOME_UNKNOWN
            ):
                return ExecutionResult(
                    journal_record.execution_id,
                    ExecutionState.OUTCOME_UNKNOWN,
                    None,
                    (),
                    (),
                    ExecutionErrorCode.EXECUTION_OUTCOME_UNKNOWN,
                    False,
                )
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
            if self._states.get(execution_id) is not ExecutionState.WAITING_APPROVAL:
                return ExecutionResult(
                    execution_id,
                    self._states.get(execution_id, ExecutionState.REQUESTED),
                    None,
                    (),
                    (),
                )
            record = existing
        else:
            execution_id = journal_record.execution_id if journal_record is not None else uuid4()
            record = IdempotencyRecord(
                request.tenant_id, request.idempotency_key, request.fingerprint, execution_id
            )
            if not self.idempotency.claim(record):
                winner = self.idempotency.get(request.tenant_id, request.idempotency_key)
                if winner is None or winner.fingerprint != request.fingerprint:
                    raise ExecutionFailure(
                        ExecutionErrorCode.IDEMPOTENCY_CONFLICT,
                        "idempotency claim could not be established",
                    )
                if winner.result is not None:
                    return winner.result
                return ExecutionResult(
                    winner.execution_id,
                    self._states.get(winner.execution_id, ExecutionState.REQUESTED),
                    None,
                    (),
                    (),
                )

        identity = ExecutionIdentity(
            execution_id,
            request.tenant_id,
            request.principal_id,
            request.agent_id,
            request.run_id,
            request.capability_id,
            request.tool_name,
            "",
            request.approval_id,
            request.request_id,
            trace_id,
        )
        self._states[execution_id] = ExecutionState.REQUESTED
        self._trace_ids[execution_id] = trace_id
        if self.journal is not None:
            self.journal.create(
                JournalRecord(
                    execution_id,
                    request.tenant_id,
                    request.principal_id,
                    request.agent_id,
                    request.run_id,
                    request.request_id,
                    request.idempotency_key,
                    request.fingerprint,
                    JournalState.REQUESTED,
                    False,
                    "",
                    request.approval_id,
                    trace_id,
                    None,
                    datetime.now(UTC),
                )
            )
        audit_ids: list[UUID] = []
        budget_reservation: Any | None = None
        try:
            self._event(request, execution_id, "execution.requested", audit_ids)
            self._event(request, execution_id, "execution.authenticated", audit_ids)
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
            try:
                policy = evaluate(
                    CapabilityRequest(
                        request.action,
                        request.resource,
                        frozenset({request.capability_id}),
                        request.risk,
                        request.reversibility,
                        request.data_class,
                        request.blast_radius,
                        request.input,
                    )
                )
            except Exception as exc:
                raise ExecutionFailure(
                    ExecutionErrorCode.POLICY_UNAVAILABLE,
                    "policy evaluation could not be established",
                ) from exc
            if policy.decision is Decision.DENY:
                self._deny(execution_id, request, ExecutionErrorCode.POLICY_DENIED, audit_ids)
            if policy.decision is Decision.REQUIRE_AUTHORIZATION and not policy.requires_approval:
                self._deny(
                    execution_id,
                    request,
                    ExecutionErrorCode.ADDITIONAL_AUTHORIZATION_REQUIRED,
                    audit_ids,
                )
            if policy.decision is not Decision.ALLOW and not policy.requires_approval:
                self._deny(
                    execution_id,
                    request,
                    ExecutionErrorCode.AUTHORIZATION_DENIED,
                    audit_ids,
                )
            policy_id = f"{policy.policy_id}:{policy.policy_version}"
            identity = ExecutionIdentity(
                execution_id,
                request.tenant_id,
                request.principal_id,
                request.agent_id,
                request.run_id,
                request.capability_id,
                request.tool_name,
                policy_id,
                request.approval_id,
                request.request_id,
                trace_id,
            )
            self._identities[execution_id] = identity
            self._event(request, execution_id, "execution.identity_bound", audit_ids)
            self._event(request, execution_id, "execution.policy_evaluated", audit_ids)
            if policy.requires_approval:
                if request.approval_id is None:
                    self._journal_state(request, execution_id, ExecutionState.WAITING_APPROVAL)
                    self._event(request, execution_id, "execution.approval_required", audit_ids)
                    raise ExecutionFailure(
                        ExecutionErrorCode.APPROVAL_REQUIRED,
                        "approval is required",
                        execution_id=execution_id,
                    )
                self._require_bound_approval(request)
            elif request.approval_id is not None:
                self._require_bound_approval(request)
            effective_timeout = min(
                request.requested_timeout_seconds,
                registration.timeout_seconds,
                self.platform_max_timeout_seconds,
            )
            if effective_timeout <= 0:
                raise ExecutionFailure(ExecutionErrorCode.TIMEOUT, "effective timeout is invalid")
            if self.budget is not None:
                try:
                    budget_reservation = self.budget.reserve_scoped(
                        BudgetScope(
                            request.tenant_id,
                            request.agent_id,
                            request.run_id,
                            request.action,
                            request.resource,
                        ),
                        tool_calls=request.requested_tool_calls,
                        seconds=effective_timeout,
                    )
                except (PermissionError, TimeoutError, ValueError) as exc:
                    raise ExecutionFailure(
                        ExecutionErrorCode.BUDGET_EXCEEDED,
                        "platform execution budget could not be reserved",
                    ) from exc
                self._event(request, execution_id, "execution.budget_reserved", audit_ids)
            else:
                self._event(request, execution_id, "execution.budget_reserved", audit_ids)
            if not self.tools.supports_hard_timeout(request.tool_name):
                raise ExecutionFailure(
                    ExecutionErrorCode.TIMEOUT,
                    "tool adapter cannot enforce the authoritative execution timeout",
                )
            if request.sandbox_required or registration.sandbox_required:
                if self.sandbox is None:
                    raise ExecutionFailure(
                        ExecutionErrorCode.SANDBOX_UNAVAILABLE,
                        "required sandbox is unavailable",
                    )
                self.sandbox.establish(request)
                self._event(request, execution_id, "execution.sandbox_started", audit_ids)
            if registration.secret_required:
                if self.secrets is None:
                    raise ExecutionFailure(
                        ExecutionErrorCode.SECRET_ACCESS_DENIED,
                        "required secret authority is unavailable",
                    )
                self.secrets.authorize(request)
            elif self.secrets is not None:
                self.secrets.authorize(request)
            self._journal_state(
                request,
                execution_id,
                ExecutionState.AUTHORIZED,
                policy_decision_id=policy_id,
            )
            self._event(request, execution_id, "execution.started", audit_ids)
            started = monotonic()
            call = ToolCall(
                uuid4(),
                request.tenant_id,
                request.run_id,
                request.tool_name,
                request.capability_id,
                request.action,
                request.resource,
            )
            self._journal_state(
                request,
                execution_id,
                ExecutionState.RUNNING,
                side_effect_started=True,
            )
            try:
                permit = self.tools.issue_permit(
                    RequestContext(
                        request.request_id,
                        request.tenant_id,
                        principal,
                        "governed-execution",
                        trace_id,
                    ),
                    call,
                    CapabilityRequest(
                        request.action,
                        request.resource,
                        frozenset({request.capability_id}),
                        request.risk,
                        request.reversibility,
                        request.data_class,
                        request.blast_radius,
                        request.input,
                    ),
                )
                if permit.decision != policy:
                    raise ExecutionFailure(
                        ExecutionErrorCode.AUTHORIZATION_DENIED,
                        "tool authority decision diverged from Platform policy",
                    )
                output = self.tools.execute(
                    call,
                    permit,
                    request.approval_id,
                    self.approvals,
                    intent_fingerprint=request.fingerprint,
                    timeout_seconds=effective_timeout,
                )
            except TimeoutError:
                self._journal_state(request, execution_id, ExecutionState.TIMED_OUT)
                self._event(request, execution_id, "execution.timed_out", audit_ids)
                result = ExecutionResult(
                    execution_id,
                    ExecutionState.TIMED_OUT,
                    None,
                    (),
                    tuple(audit_ids),
                    ExecutionErrorCode.TIMEOUT,
                    False,
                )
                if budget_reservation is not None and self.budget is not None:
                    self.budget.release(budget_reservation)
                    budget_reservation = None
                self.idempotency.complete(record, result)
                if self.journal is not None:
                    self._journal_state(
                        request,
                        execution_id,
                        result.state,
                        side_effect_started=True,
                        result=result,
                    )
                self._results[execution_id] = result
                return result
            except PermissionError as exc:
                if request.approval_id is None:
                    raise ExecutionFailure(
                        ExecutionErrorCode.AUTHORIZATION_DENIED,
                        "tool execution was not authorized",
                    ) from exc
                try:
                    approval = self.approvals.get(request.approval_id, request.tenant_id)
                except (KeyError, PermissionError) as lookup_error:
                    raise ExecutionFailure(
                        ExecutionErrorCode.APPROVAL_BINDING_MISMATCH,
                        "approval could not be bound to execution",
                    ) from lookup_error
                code = {
                    ApprovalStatus.EXPIRED: ExecutionErrorCode.APPROVAL_EXPIRED,
                    ApprovalStatus.REJECTED: ExecutionErrorCode.APPROVAL_REJECTED,
                    ApprovalStatus.CONSUMED: ExecutionErrorCode.APPROVAL_REPLAY,
                }.get(approval.status, ExecutionErrorCode.APPROVAL_BINDING_MISMATCH)
                raise ExecutionFailure(code, "approval could not authorize this execution") from exc
            if request.approval_id is not None:
                self._event(request, execution_id, "approval.consumed", audit_ids)
            elapsed = monotonic() - started
            if elapsed > effective_timeout:
                self._journal_state(request, execution_id, ExecutionState.OUTCOME_UNKNOWN)
                self._event(request, execution_id, "execution.timed_out", audit_ids)
                result = ExecutionResult(
                    execution_id,
                    ExecutionState.OUTCOME_UNKNOWN,
                    None,
                    (),
                    tuple(audit_ids),
                    ExecutionErrorCode.EXECUTION_OUTCOME_UNKNOWN,
                    False,
                )
                if budget_reservation is not None and self.budget is not None:
                    self.budget.release(budget_reservation)
                    budget_reservation = None
                self.idempotency.complete(record, result)
                if self.journal is not None:
                    self._journal_state(
                        request,
                        execution_id,
                        result.state,
                        side_effect_started=True,
                        result=result,
                    )
                self._results[execution_id] = result
                return result
            if self.secrets is not None:
                try:
                    output = self.secrets.redact_output(request, output)
                except Exception as exc:
                    if budget_reservation is not None and self.budget is not None:
                        self.budget.release(budget_reservation)
                        budget_reservation = None
                    raise ExecutionFailure(
                        ExecutionErrorCode.SECRET_ACCESS_DENIED,
                        "secret redaction could not be established",
                    ) from exc
            if budget_reservation is not None and self.budget is not None:
                try:
                    self.budget.consume(budget_reservation, elapsed)
                except Exception as exc:
                    self.budget.release(budget_reservation)
                    budget_reservation = None
                    raise ExecutionFailure(
                        ExecutionErrorCode.BUDGET_EXCEEDED,
                        "execution exceeded the reserved platform budget",
                    ) from exc
                budget_reservation = None
            evidence_ids: list[UUID] = []
            if request.evidence_required:
                try:
                    item = self.evidence.append(
                        request.tenant_id, request.run_id, output, execution_id
                    )
                    evidence_ids.append(item.evidence_id)
                    self._event(
                        request,
                        execution_id,
                        "execution.evidence_committed",
                        audit_ids,
                        {"evidence_id": str(item.evidence_id)},
                    )
                except Exception as exc:
                    self._journal_state(request, execution_id, ExecutionState.FAILED)
                    self._event(request, execution_id, "execution.failed", audit_ids)
                    raise ExecutionFailure(
                        ExecutionErrorCode.EVIDENCE_FAILURE,
                        "mandatory evidence could not be committed",
                    ) from exc
            self._journal_state(request, execution_id, ExecutionState.COMPLETED)
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
            if budget_reservation is not None and self.budget is not None:
                with suppress(Exception):
                    self.budget.release(budget_reservation)
                budget_reservation = None
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
                if self.journal is not None:
                    self._journal_state(
                        request,
                        execution_id,
                        result.state,
                        side_effect_started=True,
                        result=result,
                    )
                self._results[execution_id] = result
            raise
        except Exception as exc:
            if budget_reservation is not None and self.budget is not None:
                with suppress(Exception):
                    self.budget.release(budget_reservation)
                budget_reservation = None
            self._journal_state(request, execution_id, ExecutionState.OUTCOME_UNKNOWN)
            with suppress(Exception):
                self._event(request, execution_id, "execution.failed", audit_ids)
            result = ExecutionResult(
                execution_id,
                ExecutionState.OUTCOME_UNKNOWN,
                None,
                (),
                tuple(audit_ids),
                ExecutionErrorCode.EXECUTION_OUTCOME_UNKNOWN,
                False,
            )
            self.idempotency.complete(record, result)
            self._results[execution_id] = result
            raise ExecutionFailure(
                ExecutionErrorCode.EXECUTION_OUTCOME_UNKNOWN,
                "execution outcome could not be established",
            ) from exc

    @staticmethod
    def _decode_result(payload: str) -> ExecutionResult:
        value = json.loads(payload)
        return ExecutionResult(
            UUID(value["execution_id"]),
            ExecutionState(value["state"]),
            value.get("output"),
            tuple(UUID(item) for item in value.get("evidence_ids", [])),
            tuple(UUID(item) for item in value.get("audit_event_ids", [])),
            ExecutionErrorCode(value["error_code"]) if value.get("error_code") else None,
            bool(value.get("retryable", False)),
        )

    def _require_bound_approval(self, request: ExecutionRequest) -> None:
        if request.approval_id is None:
            raise ExecutionFailure(
                ExecutionErrorCode.APPROVAL_REQUIRED,
                "approval is required",
            )
        try:
            status = self.approvals.validate_approved_for(
                request.approval_id,
                request.tenant_id,
                request.run_id,
                request.action,
                request.resource,
                intent_fingerprint=request.fingerprint,
            )
        except PermissionError as exc:
            raise ExecutionFailure(
                ExecutionErrorCode.APPROVAL_BINDING_MISMATCH,
                "approval is not valid for this execution intent",
            ) from exc
        if status == ApprovalStatus.CONSUMED:
            raise ExecutionFailure(
                ExecutionErrorCode.APPROVAL_REPLAY,
                "approval has already been consumed",
            )
        if status == ApprovalStatus.REJECTED:
            raise ExecutionFailure(
                ExecutionErrorCode.APPROVAL_REJECTED,
                "approval was rejected",
            )
        if status == ApprovalStatus.EXPIRED:
            raise ExecutionFailure(
                ExecutionErrorCode.APPROVAL_EXPIRED,
                "approval has expired",
            )
        if status is not None and status is not ApprovalStatus.APPROVED:
            raise ExecutionFailure(
                ExecutionErrorCode.APPROVAL_REQUIRED,
                "approved human review is required",
            )

    def _journal_state(
        self,
        request: ExecutionRequest,
        execution_id: UUID,
        state: ExecutionState,
        *,
        side_effect_started: bool | None = None,
        policy_decision_id: str | None = None,
        result: ExecutionResult | None = None,
    ) -> None:
        self._states[execution_id] = state
        if self.journal is not None:
            self.journal.transition(
                request.tenant_id,
                execution_id,
                JournalState(state.value),
                side_effect_started=side_effect_started,
                policy_decision_id=policy_decision_id,
                result_json=encode_result(result) if result is not None else None,
            )

    def status(self, tenant_id: str, execution_id: UUID) -> ExecutionResult:
        if not tenant_id or tenant_id != tenant_id.strip():
            raise ValueError("tenant identifier must be normalized")
        result = self._results.get(execution_id)
        identity = self._identities.get(execution_id)
        journal_record = (
            self.journal.get(tenant_id, execution_id) if self.journal is not None else None
        )  # noqa: E501
        if result is None and journal_record is not None and journal_record.result_json:
            return self._decode_result(journal_record.result_json)
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
            return cast(
                AgentDefinition,
                self.agents.get(request.tenant_id, request.agent_id, version),
            )
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
            or registration.capability_version != request.capability_version
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
        if registration.risk is RiskTier.PROHIBITED:
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
        self._journal_state(request, execution_id, ExecutionState.DENIED)
        self._event(request, execution_id, "authorization.denied", audit_ids)
        raise ExecutionFailure(code, "execution denied")

    def _event(
        self,
        request: ExecutionRequest,
        execution_id: UUID,
        event_type: str,
        audit_ids: list[UUID],
        extra: Mapping[str, str] | None = None,
    ) -> None:
        identity = self._identities.get(execution_id)
        payload: dict[str, str] = {
            "request_id": request.request_id,
            "principal_id": request.principal_id,
            "agent_id": str(request.agent_id),
            "capability_id": request.capability_id,
            "tool_name": request.tool_name,
            "execution_id": str(execution_id),
        }
        if request.approval_id is not None:
            payload["approval_id"] = str(request.approval_id)
        trace_id = self._trace_ids.get(execution_id)
        if trace_id is not None:
            payload["trace_id"] = trace_id
        if identity is not None and identity.policy_decision_id:
            payload["policy_decision_id"] = identity.policy_decision_id
        if extra:
            payload.update(extra)
        event = new_event(request.tenant_id, request.run_id, event_type, payload)
        stored = self.events.append(event)
        audit_ids.append(stored.event_id)
