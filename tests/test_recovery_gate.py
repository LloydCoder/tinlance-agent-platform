"""Canonical P10 recovery objective and failure-injection contract tests."""
import pytest

from tinlance_agent_platform_durability.recovery import (
    FailureMode,
    RecoveryDrill,
    RecoveryGate,
    RecoveryObjective,
)


@pytest.mark.parametrize("failure_mode", list(FailureMode))
def test_recovery_gate_accepts_evidenced_drill_within_rto_and_rpo(failure_mode) -> None:
    drill = RecoveryDrill(
        drill_id=f"p10-{failure_mode.value}",
        failure_mode=failure_mode,
        objective=RecoveryObjective(rto_seconds=60, rpo_seconds=5),
        observed_rto_seconds=45,
        observed_rpo_seconds=0,
        evidence_ref=f"evidence://p10/{failure_mode.value}",
    )
    RecoveryGate((drill,)).evaluate()


@pytest.mark.parametrize(
    ("observed_rto", "observed_rpo"),
    [(61, 0), (60, 6), (61, 6)],
)
def test_recovery_gate_fails_closed_when_rto_or_rpo_is_exceeded(
    observed_rto: int, observed_rpo: int
) -> None:
    drill = RecoveryDrill(
        drill_id="p10-failed-drill",
        failure_mode=FailureMode.WORKER_CRASH,
        objective=RecoveryObjective(rto_seconds=60, rpo_seconds=5),
        observed_rto_seconds=observed_rto,
        observed_rpo_seconds=observed_rpo,
        evidence_ref="evidence://p10/failure",
    )
    with pytest.raises(RuntimeError, match="recovery gate failed"):
        RecoveryGate((drill,)).evaluate()


def test_recovery_gate_rejects_empty_drill_set() -> None:
    with pytest.raises(ValueError, match="requires drills"):
        RecoveryGate(()).evaluate()


def test_recovery_drill_requires_evidence_reference() -> None:
    with pytest.raises(ValueError, match="identifier and evidence"):
        RecoveryDrill(
            drill_id="p10-missing-evidence",
            failure_mode=FailureMode.DATABASE_OUTAGE,
            objective=RecoveryObjective(rto_seconds=60, rpo_seconds=5),
            observed_rto_seconds=10,
            observed_rpo_seconds=0,
            evidence_ref=" ",
        )
