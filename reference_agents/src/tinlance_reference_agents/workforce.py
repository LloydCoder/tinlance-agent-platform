"""Reference enterprise workforce catalog.

These are governed reference profiles, not privileged runtime principals.
Execution authority still comes from Agent Platform policy and authorization.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final


_ROLE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


@dataclass(frozen=True, slots=True)
class WorkforceRole:
    """Immutable, deterministic description of a reference enterprise role."""

    role_id: str
    function: str
    mission: str
    capabilities: tuple[str, ...]
    escalation_target: str

    def __post_init__(self) -> None:
        role_id = self.role_id.strip()
        function = self.function.strip()
        mission = self.mission.strip()
        escalation_target = self.escalation_target.strip()
        capabilities = tuple(capability.strip() for capability in self.capabilities)

        if not _ROLE_ID.fullmatch(role_id):
            raise ValueError("role_id must be a lowercase hyphenated stable identifier")
        if not function or not mission:
            raise ValueError("workforce role identity and mission are required")
        if not capabilities or any(not capability for capability in capabilities):
            raise ValueError("workforce role requires non-empty capabilities")
        if len(set(capabilities)) != len(capabilities):
            raise ValueError("workforce role capabilities must be unique")
        if not escalation_target:
            raise ValueError("workforce role requires an escalation target")

        object.__setattr__(self, "role_id", role_id)
        object.__setattr__(self, "function", function)
        object.__setattr__(self, "mission", mission)
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "escalation_target", escalation_target)

    def as_dict(self) -> dict[str, object]:
        """Return a deterministic, authority-free catalog representation."""
        return {
            "role_id": self.role_id,
            "function": self.function,
            "mission": self.mission,
            "capabilities": list(self.capabilities),
            "escalation_target": self.escalation_target,
        }


REFERENCE_WORKFORCE: Final[tuple[WorkforceRole, ...]] = (
    WorkforceRole(
        "executive",
        "Executive",
        "Coordinate enterprise priorities and decisions",
        ("strategy", "portfolio", "risk"),
        "human-executive",
    ),
    WorkforceRole(
        "research",
        "Research",
        "Produce evidence-backed research and synthesis",
        ("research", "analysis", "evidence"),
        "human-research-lead",
    ),
    WorkforceRole(
        "finance",
        "Finance",
        "Operate governed financial analysis and reconciliation",
        ("finance", "reconciliation", "forecasting"),
        "human-finance-lead",
    ),
    WorkforceRole(
        "security",
        "Security",
        "Detect, assess and respond to security risk",
        ("security", "incident-response", "threat-analysis"),
        "human-ciso",
    ),
    WorkforceRole(
        "engineering",
        "Engineering",
        "Design, implement and verify technical systems",
        ("software", "architecture", "testing"),
        "human-engineering-lead",
    ),
    WorkforceRole(
        "sales",
        "Sales",
        "Qualify opportunities and manage governed commercial execution",
        ("qualification", "pipeline", "account-research"),
        "human-sales-lead",
    ),
    WorkforceRole(
        "marketing",
        "Marketing",
        "Produce governed market intelligence and campaigns",
        ("content", "campaigns", "market-analysis"),
        "human-marketing-lead",
    ),
    WorkforceRole(
        "operations",
        "Operations",
        "Coordinate reliable business operations and workflows",
        ("operations", "workflow", "capacity"),
        "human-operations-lead",
    ),
    WorkforceRole(
        "customer-success",
        "Customer Success",
        "Monitor adoption, outcomes and customer risk",
        ("adoption", "health", "retention"),
        "human-customer-success-lead",
    ),
    WorkforceRole(
        "procurement",
        "Procurement",
        "Evaluate suppliers and governed purchasing workflows",
        ("supplier-analysis", "sourcing", "procurement"),
        "human-procurement-lead",
    ),
    WorkforceRole(
        "compliance",
        "Compliance",
        "Map controls, evidence and regulatory obligations",
        ("controls", "evidence", "regulatory-mapping"),
        "human-compliance-lead",
    ),
)

_REFERENCE_WORKFORCE_BY_ID: Final[dict[str, WorkforceRole]] = {
    role.role_id: role for role in REFERENCE_WORKFORCE
}

if len(_REFERENCE_WORKFORCE_BY_ID) != len(REFERENCE_WORKFORCE):
    raise RuntimeError("reference workforce role IDs must be unique")


def get_reference_workforce(
    role_id: str | None = None,
) -> tuple[WorkforceRole, ...] | WorkforceRole:
    """Return the immutable catalog, or one role by its stable identifier."""
    if role_id is None:
        return REFERENCE_WORKFORCE
    normalized = role_id.strip()
    try:
        return _REFERENCE_WORKFORCE_BY_ID[normalized]
    except KeyError as exc:
        raise KeyError(f"unknown reference workforce role: {normalized!r}") from exc
