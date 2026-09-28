"""Versioned execution boundary contract; implementations are separate adapters."""
from dataclasses import dataclass
from uuid import UUID
from .models import DataClass,RiskTier
@dataclass(frozen=True,slots=True)
class ApprovalRef:
 approval_id:UUID; approver_subject_id:str; policy_id:str; policy_version:str
@dataclass(frozen=True,slots=True)
class ExecutionLimits:
 timeout_seconds:int; memory_mb:int; cpu_seconds:int; pids:int
 def __post_init__(self)->None:
  if min(self.timeout_seconds,self.memory_mb,self.cpu_seconds,self.pids)<=0: raise ValueError("execution limits must be positive")
@dataclass(frozen=True,slots=True)
class ExecutionRequest:
 contract_version:str; request_id:UUID; tenant_id:UUID; actor_id:str; action:str; workspace:str; command:tuple[str,...]; risk:RiskTier; data_class:DataClass; limits:ExecutionLimits; approval:ApprovalRef|None=None; allow_network:bool=False; allowed_env:tuple[str,...]=()
 def __post_init__(self)->None:
  if self.contract_version!="1": raise ValueError("unsupported execution contract version")
  if not self.command: raise ValueError("command cannot be empty")
  if self.risk in {RiskTier.HIGH,RiskTier.CRITICAL} and self.approval is None: raise PermissionError("high-risk execution requires approval")
  if self.risk is RiskTier.PROHIBITED: raise PermissionError("prohibited execution is never permitted")
  if self.allow_network and self.data_class in {DataClass.RESTRICTED,DataClass.SECRET}: raise PermissionError("restricted/secret execution cannot enable network")
@dataclass(frozen=True,slots=True)
class ExecutionResultRef:
 execution_id:UUID; request_id:UUID; trajectory_ref:str; evidence_ref:str; exit_code:int