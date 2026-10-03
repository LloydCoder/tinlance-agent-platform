"""Adversarial agent security regression contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AttackClass(StrEnum):
    GOAL_HIJACKING = "goal_hijacking"
    TOOL_MISUSE = "tool_misuse"
    IDENTITY_PRIVILEGE_ABUSE = "identity_privilege_abuse"
    MEMORY_POISONING = "memory_poisoning"
    INTER_AGENT_ATTACK = "inter_agent_attack"
    CASCADING_FAILURE = "cascading_failure"
    TRUST_EXPLOITATION = "trust_exploitation"
    DATA_EXFILTRATION = "data_exfiltration"
    SANDBOX_ESCAPE = "sandbox_escape"
    RESOURCE_EXHAUSTION = "resource_exhaustion"


@dataclass(frozen=True, slots=True)
class AdversarialCase:
    case_id: str
    attack_class: AttackClass
    expected_blocked: bool
    observed_blocked: bool
    evidence_ref: str

    def __post_init__(self) -> None:
        if not self.case_id.strip() or not self.evidence_ref.strip():
            raise ValueError("adversarial cases require an identifier and evidence")
        if not self.expected_blocked:
            raise ValueError("security regression cases must declare a blocking expectation")


@dataclass(frozen=True, slots=True)
class AdversarialGate:
    name: str
    cases: tuple[AdversarialCase, ...]

    def evaluate(self) -> None:
        if not self.name.strip() or not self.cases:
            raise ValueError("adversarial gate requires a name and cases")
        failures = [case.case_id for case in self.cases if not case.observed_blocked]
        if failures:
            raise RuntimeError("adversarial security gate failed: " + ", ".join(failures))
