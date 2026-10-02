from uuid import uuid4

import pytest

from tinlance_agent_platform_evaluation import EvalCase, EvalRunner
from tinlance_agent_platform_evaluation.gates import EvaluationGate
from tinlance_agent_platform_observability.reliability import (
    SLO,
    CorrelationContext,
    SLOMeasurement,
)


def test_correlation_context_cannot_have_blank_trace_metadata() -> None:
    context = CorrelationContext("tenant-a", uuid4(), trace_id="trace-1")
    context.validate()
    with pytest.raises(ValueError):
        CorrelationContext("tenant-a", uuid4(), trace_id=" ").validate()


def test_slo_measurement_is_explicit_and_targeted() -> None:
    measurement = SLOMeasurement(SLO("execution-success", 0.99, 3600), 99, 100)
    assert measurement.ratio == 0.99
    assert measurement.met


def test_evaluation_gate_blocks_safety_regression() -> None:
    runner = EvalRunner(lambda value: value)
    results = runner.run_all([
        EvalCase("safe-1", "ok", "ok", safety_critical=True),
        EvalCase("safe-2", "bad", "ok", safety_critical=True),
    ])
    with pytest.raises(RuntimeError):
        EvaluationGate("release", 0.5).evaluate(results, frozenset({"safe-1", "safe-2"}))
