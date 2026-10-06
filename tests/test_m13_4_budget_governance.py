from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from tinlance_agent_platform_budgets import (
    BudgetScope,
    BudgetService,
    TenantQuotaService,
)
from tinlance_agent_platform_contracts import Budget


def make_budget(max_calls: int = 2) -> Budget:
    return Budget(uuid4(), "tenant-a", uuid4(), 10, 60.0, max_calls)


def test_scoped_budget_binds_agent_action_and_resource() -> None:
    budget = make_budget()
    service = BudgetService(budget)
    scope = BudgetScope(
        "tenant-a",
        uuid4(),
        budget.run_id,
        "invoice.refund",
        "invoice:123",
    )
    reservation = service.reserve_scoped(scope, tool_calls=1, seconds=5.0)
    assert reservation.scope == scope
    with pytest.raises(PermissionError):
        service.reserve_scoped(
            BudgetScope(
                "tenant-b",
                scope.agent_id,
                scope.run_id,
                scope.action,
                scope.resource,
            ),
            tool_calls=1,
            seconds=1.0,
        )


def test_quota_reservation_is_atomic_under_parallel_admission() -> None:
    quota = TenantQuotaService(
        max_concurrency=1,
        max_tool_calls=1,
        max_token_units=100,
        max_cost_units=10.0,
    )

    def attempt() -> bool:
        try:
            quota.reserve(
                reservation_id=str(uuid4()),
                tenant_id="tenant-a",
                agent_id=str(uuid4()),
                run_id=str(uuid4()),
                action="write",
                resource="resource:1",
                concurrency=1,
                tool_calls=1,
            )
            return True
        except TimeoutError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: attempt(), range(8)))
    assert sum(results) == 1


def test_quota_replay_cannot_change_scope() -> None:
    quota = TenantQuotaService(
        max_concurrency=2,
        max_tool_calls=2,
        max_token_units=100,
        max_cost_units=10.0,
    )
    reservation = quota.reserve(
        reservation_id="reservation-1",
        tenant_id="tenant-a",
        agent_id="agent-a",
        run_id="run-a",
        action="write",
        resource="resource-a",
        concurrency=1,
        tool_calls=1,
    )
    assert (
        quota.reserve(
            reservation_id="reservation-1",
            tenant_id="tenant-a",
            agent_id="agent-a",
            run_id="run-a",
            action="write",
            resource="resource-a",
            concurrency=1,
            tool_calls=1,
        )
        == reservation
    )
    with pytest.raises(ValueError):
        quota.reserve(
            reservation_id="reservation-1",
            tenant_id="tenant-a",
            agent_id="agent-b",
            run_id="run-a",
            action="write",
            resource="resource-a",
            concurrency=1,
            tool_calls=1,
        )
