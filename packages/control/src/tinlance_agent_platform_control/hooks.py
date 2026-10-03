"""Portable runtime interception contracts without alternate authority paths."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class ControlDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_REVIEW = "require_review"


@dataclass(frozen=True, slots=True)
class ControlEvent:
    event_type: str
    tenant_id: str
    execution_id: str
    action: str
    attributes: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if any(not value.strip() for value in (self.event_type, self.tenant_id, self.execution_id, self.action)):
            raise ValueError("control event identity fields are required")


class ControlHook(Protocol):
    def evaluate(self, event: ControlEvent) -> ControlDecision: ...


def enforce_control(decision: ControlDecision) -> None:
    """Map a hook result to a fail-closed boundary; never grant authority."""
    if decision is ControlDecision.DENY:
        raise PermissionError("runtime control denied the action")
    if decision is ControlDecision.REQUIRE_REVIEW:
        raise PermissionError("runtime control requires explicit review")
