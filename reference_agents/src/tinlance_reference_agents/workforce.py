"""Reference enterprise workforce catalog.

These are governed reference profiles, not privileged runtime principals.
Execution authority still comes from Agent Platform policy and authorization.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class WorkforceRole:
    role_id: str
    function: str
    mission: str
    capabilities: tuple[str, ...]
    escalation_target: str

    def __post_init__(self) -> None:
        if not self.role_id or not self.function or not self.mission:
            raise ValueError("workforce role identity and mission are required")
        if not self.capabilities:
            raise ValueError("workforce role requires capabilities")
        if not self.escalation_target:
            raise ValueError("workforce role requires an escalation target")


REFERENCE_WORKFORCE: Final[tuple[WorkforceRole, ...]] = (
    WorkforceRole(
        "executive", "Executive", "Coordinate enterprise priorities and decisions",
        ("strategy", "portfolio", "risk"), "human-executive",
    ),
    WorkforceRole(
        "research", "Research", "Produce evidence-backed research and synthesis",
        ("research", "analysis", "evidence"), "human-research-lead",
    ),
    WorkforceRole(
        "finance", "Finance", "Operate governed financial analysis and reconciliation",
        ("finance", "reconciliation", "forecasting"), "human-finance-lead",
    ),
    WorkforceRole(
        "security", "Security", "Detect, assess and respond to security risk",
        ("security", "incident-response", "threat-analysis"), "human-ciso",
    ),
    WorkforceRole(
        "engineering", "Engineering", "Design, implement and verify technical systems",
        ("software", "architecture", "testing"), "human-engineering-lead",
    ),
    WorkforceRole(
        "sales", "Sales", "Qualify opportunities and manage governed commercial execution",
        ("qualification", "pipeline", "account-research"), "human-sales-lead",
    ),
    WorkforceRole(
        "marketing", "Marketing", "Produce governed market intelligence and campaigns",
        ("content", "campaigns", "market-analysis"), "human-marketing-lead",
    ),
    WorkforceRole(
        "operations", "Operations", "Coordinate reliable business operations and workflows",
        ("operations", "workflow", "capacity"), "human-operations-lead",
    ),
    WorkforceRole(
        "customer-success", "Customer Success", "Monitor adoption, outcomes and customer risk",
        ("adoption", "health", "retention"), "human-customer-success-lead",
    ),
    WorkforceRole(
        "procurement", "Procurement", "Evaluate suppliers and governed purchasing workflows",
        ("supplier-analysis", "sourcing", "procurement"), "human-procurement-lead",
    ),
    WorkforceRole(
        "compliance", "Compliance", "Map controls, evidence and regulatory obligations",
        ("controls", "evidence", "regulatory-mapping"), "human-compliance-lead",
    ),
)


def get_reference_workforce() -> tuple[WorkforceRole, ...]:
    return REFERENCE_WORKFORCE
