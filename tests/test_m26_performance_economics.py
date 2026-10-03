import pytest

from tinlance_agent_platform_budgets import (
    CapacityEnvelope,
    CapacityGate,
    CapacityObservation,
    TenantQuota,
)


def test_capacity_gate_accepts_observed_envelope() -> None:
    envelope = CapacityEnvelope(100, 500, 900, 50)
    observation = CapacityObservation(120, 300, 700, 40)
    CapacityGate(envelope, observation, "evidence://capacity/1").evaluate()


def test_capacity_gate_blocks_latency_regression() -> None:
    gate = CapacityGate(
        CapacityEnvelope(100, 500, 900, 50),
        CapacityObservation(120, 600, 700, 40),
        "evidence://capacity/fail",
    )
    with pytest.raises(RuntimeError, match="p95"):
        gate.evaluate()


def test_tenant_quota_prevents_noisy_neighbor_overrun() -> None:
    quota = TenantQuota(10, 100, 1000, 50.0)
    assert quota.admits(concurrency=5, tool_calls=50, token_units=500, cost_units=10)
    assert not quota.admits(concurrency=11, tool_calls=50, token_units=500, cost_units=10)


def test_capacity_contract_rejects_invalid_values() -> None:
    with pytest.raises(ValueError):
        CapacityEnvelope(-1, 100, 100, 1)
