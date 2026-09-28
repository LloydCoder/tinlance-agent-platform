"""Versioned M1 domain contracts."""
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from uuid import UUID

API_VERSION = "1.0"

class TaskStatus(StrEnum):
    QUEUED="queued"; RUNNING="running"; PAUSED="paused"; SUCCEEDED="succeeded"; FAILED="failed"; CANCELLED="cancelled"
class RunStatus(StrEnum):
    CREATED="created"; RUNNING="running"; WAITING_APPROVAL="waiting_approval"; SUCCEEDED="succeeded"; FAILED="failed"; CANCELLED="cancelled"
class ApprovalStatus(StrEnum):
    PENDING="pending"; APPROVED="approved"; REJECTED="rejected"; EXPIRED="expired"
class ToolCallStatus(StrEnum):
    PROPOSED="proposed"; BLOCKED="blocked"; APPROVAL_REQUIRED="approval_required"; EXECUTED="executed"; FAILED="failed"

@dataclass(frozen=True, slots=True)
class AgentDefinition:
    agent_id: UUID; tenant_id: str; name: str; version: str; owner_subject_id: str; policy_profile: str
    capabilities: frozenset[str]; instructions_hash: str
    def __post_init__(self)->None:
        if not all((self.tenant_id,self.name,self.version,self.owner_subject_id)): raise ValueError("agent definition identity fields must be non-empty")
        if not self.capabilities: raise ValueError("agent definition must declare capabilities")

@dataclass(frozen=True, slots=True)
class TaskSpec:
    task_id: UUID; tenant_id: str; agent_id: UUID; agent_version: str; requester_subject_id: str; objective: str
    max_turns: int=20; timeout_seconds: float=300.0
    def __post_init__(self)->None:
        if not self.tenant_id or not self.objective: raise ValueError("task identity and objective are required")
        if self.max_turns<1 or self.timeout_seconds<=0: raise ValueError("task limits must be positive")

@dataclass(frozen=True, slots=True)
class Run:
    run_id: UUID; task_id: UUID; tenant_id: str; status: RunStatus=RunStatus.CREATED; turn_count: int=0
    approval_id: UUID|None=None; failure_code: str|None=None

@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    approval_id: UUID; tenant_id: str; run_id: UUID; action: str; resource: str; reason: str; requested_by: str
    status: ApprovalStatus=ApprovalStatus.PENDING; metadata: dict[str,Any]=field(default_factory=dict)

@dataclass(frozen=True, slots=True)
class Budget:
    budget_id: UUID; tenant_id: str; run_id: UUID; max_turns: int; max_seconds: float; max_tool_calls: int
    consumed_turns: int=0; consumed_tool_calls: int=0; elapsed_seconds: float=0.0

@dataclass(frozen=True, slots=True)
class ToolCall:
    call_id: UUID; tenant_id: str; run_id: UUID; tool_name: str; capability: str; action: str; resource: str
    status: ToolCallStatus=ToolCallStatus.PROPOSED

@dataclass(frozen=True, slots=True)
class SandboxRequest:
    request_id: UUID; tenant_id: str; run_id: UUID; workspace_id: str; command: tuple[str,...]; timeout_seconds: float
    network: bool=False; allowed_paths: tuple[str,...]=(); environment_keys: tuple[str,...]=()

@dataclass(frozen=True, slots=True)
class ExecutionResult:
    call_id: UUID; exit_code: int; stdout: str; stderr: str; duration_seconds: float; evidence_ids: tuple[UUID,...]=()

@dataclass(frozen=True, slots=True)
class EvidenceLink:
    tenant_id: str; run_id: UUID; action_id: UUID; evidence_id: UUID; sequence: int
