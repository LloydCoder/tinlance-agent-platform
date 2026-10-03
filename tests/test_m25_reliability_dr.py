import pytest

from tinlance_agent_platform_durability import (
    FailureMode,
    RecoveryDrill,
    RecoveryGate,
    RecoveryObjective,
)


def test_recovery_gate_accepts_drills_within_rto_rpo() -> None:
    drill = RecoveryDrill(
        "drill-1",
        FailureMode.WORKER_CRASH,
        RecoveryObjective(60, 30),
        40,
        10,
        "evidence://dr/1",
    )
    assert drill.passed
    RecoveryGate((drill,)).evaluate()


def test_recovery_gate_blocks_failed_drill() -> None:
    drill = RecoveryDrill(
        "drill-fail",
        FailureMode.DATABASE_OUTAGE,
        RecoveryObjective(60, 30),
        90,
        10,
        "evidence://dr/fail",
    )
    with pytest.raises(RuntimeError, match="drill-fail"):
        RecoveryGate((drill,)).evaluate()


def test_recovery_contract_requires_non_negative_values_and_evidence() -> None:
    with pytest.raises(ValueError):
        RecoveryObjective(-1, 0)
    with pytest.raises(ValueError):
        RecoveryDrill(
            "",
            FailureMode.QUEUE_OUTAGE,
            RecoveryObjective(1, 1),
            0,
            0,
            "evidence://x",
        )
