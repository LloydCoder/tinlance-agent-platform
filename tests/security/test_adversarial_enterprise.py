from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from tinlance_agent_platform_approvals import ApprovalService
from tinlance_agent_platform_budgets import BudgetService
from tinlance_agent_platform_contracts import (
    AgentIdentity,
    Budget,
    DataClass,
    Event,
    RiskTier,
    Reversibility,
)
from tinlance_agent_platform_durability import IdempotencyStore, RetryPolicy
from tinlance_agent_platform_events import InMemoryEventStore, new_event
from tinlance_agent_platform_mcp import MCPTool, MCPToolGateway, ToolScope
from tinlance_agent_platform_observability import (
    InMemoryObservabilitySink,
    new_security_event,
)


def test_agent_identity_rejects_untrusted_normalization() -> None:
    with pytest.raises(ValueError):
        AgentIdentity(
            uuid4(),
            " tenant-a",
            "worker",
            "1.0",
            "owner",
            "default",
            "trusted",
            "prod",
        )


def test_event_store_rejects_sensitive_values_and_exposes_immutable_history() -> None:
    store = InMemoryEventStore()
    event = new_event("tenant-a", uuid4(), "tool.executed", {"outcome": "allow"})
    stored = store.append(event)
    with pytest.raises(TypeError):
        stored.payload["outcome"] = "deny"  # type: ignore[index]
    assert store.list_for_run("tenant-a", event.run_id) == (stored,)

    sensitive = new_event("tenant-a", uuid4(), "tool.executed", {"result": "bearer token leaked"})
    with pytest.raises(ValueError):
        store.append(sensitive)


def test_observability_history_is_immutable_to_callers() -> None:
    sink = InMemoryObservabilitySink()
    sink.emit_security(new_security_event("tenant-a", "tool.denied", "warning", outcome="deny"))
    history = sink.security
    assert isinstance(history, tuple)
    with pytest.raises(AttributeError):
        history.append(object())  # type: ignore[attr-defined]


def test_mcp_gateway_rejects_unbounded_or_unsupported_arguments() -> None:
    class Transport:
        def call(self, tool_name: str, arguments: object, scope: ToolScope) -> dict[str, object]:
            return {"ok": True}

    gateway = MCPToolGateway(Transport())
    gateway.register(MCPTool("lookup", "lookup", "doc:read", "doc-1"))
    scope = ToolScope("tenant-a", "doc:read", "doc-1")

    with pytest.raises(ValueError):
        gateway.call(scope, "lookup", {"nested": {"deep": {"x": {"y": {"z": {"q": {"r": {"s": {"t": 1}}}}}}}}})

    with pytest.raises(TypeError):
        gateway.call(scope, "lookup", {"value": object()})


def test_idempotency_claim_is_atomic_across_concurrent_callers() -> None:
    store = IdempotencyStore()
    run_id = uuid4()

    def claim() -> bool:
        return store.claim("tenant-a", "same-request", run_id)

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(lambda _: claim(), range(100)))

    assert all(results)


def test_budget_consumption_is_atomic_across_concurrent_callers() -> None:
    budget = Budget(uuid4(), "tenant-a", 100, 1000.0, 100)
    service = BudgetService(budget)

    def consume() -> None:
        service.consume_turn(1.0)

    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(consume) for _ in range(100)]
        for future in futures:
            future.result()

    assert service.budget.consumed_turns == 100
    assert service.budget.elapsed_seconds == 100.0


def test_approval_decision_is_single_use_under_concurrency() -> None:
    service = ApprovalService()
    item = service.request(
        "tenant-a",
        uuid4(),
        "delete",
        "doc-1",
        "approved test action",
        "user-1",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )

    def decide() -> str:
        try:
            service.decide(item.approval_id, True, "tenant-a")
        except ValueError:
            return "lost"
        return "won"

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: decide(), range(8)))

    assert results.count("won") == 1


def test_retry_policy_rejects_invalid_configuration() -> None:
    with pytest.raises(ValueError):
        RetryPolicy(max_attempts=0)
    with pytest.raises(ValueError):
        RetryPolicy(base_delay_seconds=10.0, max_delay_seconds=1.0)
