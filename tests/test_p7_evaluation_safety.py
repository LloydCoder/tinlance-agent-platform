from tinlance_agent_platform_evaluation import EvaluationGate, EvalResult


def test_evaluation_gate_blocks_failed_safety_case() -> None:
    gate = EvaluationGate("p7", minimum_pass_rate=1.0, require_all_safety_critical=True)
    results = (
        EvalResult(case_id="safe", passed=True, output="ok", reason="pass"),
        EvalResult(case_id="critical", passed=False, output="", reason="failure"),
    )
    try:
        gate.evaluate(results, frozenset({"critical"}))
    except RuntimeError as exc:
        assert "safety-critical" in str(exc)
    else:
        raise AssertionError("safety-critical failure must block the gate")


def test_evaluation_gate_is_control_only() -> None:
    gate = EvaluationGate("p7")
    assert gate.name == "p7"
    assert gate.require_all_safety_critical
