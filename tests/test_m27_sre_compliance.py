import pytest

from tinlance_agent_platform_operations import (
    AlertRule,
    ErrorBudget,
    IncidentEvidence,
    Severity,
)


def test_error_budget_tracks_exhaustion() -> None:
    budget = ErrorBudget(0.99, 990, 1000)
    assert budget.allowed_failure_ratio == 0.01
    assert not budget.exhausted
    exhausted = ErrorBudget(0.99, 980, 1000)
    assert exhausted.exhausted


def test_alert_rule_and_incident_evidence() -> None:
    alert = AlertRule("error-rate", Severity.CRITICAL, 0.05)
    assert alert.triggers(0.05)
    incident = IncidentEvidence(
        "inc-1",
        Severity.CRITICAL,
        "provider outage",
        ("evidence://incident/1",),
    )
    assert incident.incident_id == "inc-1"
    with pytest.raises(ValueError):
        IncidentEvidence("inc-2", Severity.WARNING, "missing evidence", ())


def test_error_budget_requires_observations() -> None:
    budget = ErrorBudget(0.99, 0, 0)
    with pytest.raises(ValueError):
        assert budget.observed_failure_ratio >= 0
