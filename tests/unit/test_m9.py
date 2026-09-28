import pytest
from tinlance_agent_platform_evaluation import EvalCase, EvalRunner


def test_eval_runner_is_deterministic() -> None:
    runner = EvalRunner(lambda value: value.upper())
    result = runner.run(EvalCase("E1", "ok", "OK"))
    assert result.passed


def test_safety_critical_regression_fails_closed() -> None:
    runner = EvalRunner(lambda _value: "bad")
    with pytest.raises(RuntimeError):
        runner.run_all([EvalCase("E2", "unsafe", "safe", safety_critical=True)])
