from uuid import uuid4

import pytest
from tinlance_agent_platform_durability import IdempotencyStore, RetryPolicy


def test_idempotency_is_tenant_scoped() -> None:
    store = IdempotencyStore()
    run_a = uuid4()
    run_b = uuid4()
    assert store.claim("a", "k", run_a)
    assert store.claim("a", "k", run_a)
    assert not store.claim("a", "k", run_b)
    assert store.claim("b", "k", run_b)


def test_retry_policy_is_bounded() -> None:
    policy = RetryPolicy(max_attempts=3, base_delay_seconds=2, max_delay_seconds=5)
    assert [policy.delay(i) for i in (1, 2, 3)] == [2, 4, 5]
    with pytest.raises(ValueError):
        policy.delay(4)
