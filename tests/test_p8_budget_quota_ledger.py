from pathlib import Path
from uuid import UUID, uuid4

import pytest

from tinlance_agent_platform_budgets import (
    BudgetScope,
    BudgetService,
    CapacityEnvelope,
    CapacityGate,
    CapacityObservation,
    PostgresQuotaLedger,
    QuotaReservationRequest,
    QuotaSettlement,
    TenantQuotaService,
)

ROOT = Path(__file__).resolve().parents[1]
TENANT_ID = UUID("00000000-0000-0000-0000-000000000071")
AGENT_ID = UUID("10000000-0000-0000-0000-000000000071")
RUN_ID = UUID("20000000-0000-0000-0000-000000000071")


class Cursor:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class Connection:
    def __init__(self, *, autocommit=False, result=True):
        self.autocommit = autocommit
        self.result = result
        self.queries = []
        self.committed = False
        self.closed = False

    def execute(self, query, params=()):
        self.queries.append((query, params))
        if "platform.reserve_quota" in query:
            return Cursor((params[0],))
        if "platform.settle_quota" in query:
            return Cursor((self.result if isinstance(self.result, str) else "settled",))
        return Cursor((self.result if isinstance(self.result, bool) else True,))

    def commit(self):
        self.committed = True

    def close(self):
        self.closed = True


def request(*, reservation_id=None, cost_units=1.25):
    return QuotaReservationRequest(
        tenant_id=TENANT_ID,
        agent_id=AGENT_ID,
        run_id=RUN_ID,
        action="invoice.refund",
        resource="invoice:123",
        idempotency_key="p8-reservation-key-0001",
        concurrency=1,
        tool_calls=1,
        token_units=100,
        cost_units=cost_units,
        reservation_id=reservation_id,
    )


def test_settled_quota_releases_concurrency_but_retains_consumption() -> None:
    quota = TenantQuotaService(
        max_concurrency=1,
        max_tool_calls=3,
        max_token_units=300,
        max_cost_units=5.0,
    )
    first = quota.reserve(
        reservation_id="reservation-0001",
        tenant_id="tenant-a",
        agent_id="agent-a",
        run_id="run-a",
        action="read",
        resource="resource-a",
        concurrency=1,
        tool_calls=1,
        token_units=100,
        cost_units=1.0,
    )
    quota.settle(first)
    assert quota.consumed == (0, 1, 100, 1.0)

    second = quota.reserve(
        reservation_id="reservation-0002",
        tenant_id="tenant-a",
        agent_id="agent-a",
        run_id="run-b",
        action="read",
        resource="resource-b",
        concurrency=1,
        tool_calls=1,
        token_units=100,
        cost_units=1.0,
    )
    assert second.reservation_id == "reservation-0002"


def test_quota_rejects_non_finite_and_boolean_dimensions() -> None:
    with pytest.raises(ValueError, match="quota values"):
        TenantQuotaService(
            max_concurrency=1,
            max_tool_calls=1,
            max_token_units=1,
            max_cost_units=float("nan"),
        )
    quota = TenantQuotaService(
        max_concurrency=1, max_tool_calls=1, max_token_units=1, max_cost_units=1.0
    )
    with pytest.raises(ValueError, match="dimensions"):
        quota.reserve(
            reservation_id="reservation-0001",
            tenant_id="tenant-a",
            agent_id="agent-a",
            run_id="run-a",
            action="read",
            resource="resource-a",
            concurrency=True,
        )


def test_capacity_gate_reports_actual_envelope_compliance() -> None:
    gate = CapacityGate(
        CapacityEnvelope(100.0, 200.0, 400.0, 20),
        CapacityObservation(50.0, 150.0, 300.0, 10),
        "evidence:capacity-run",
    )
    assert gate.within is False
    with pytest.raises(RuntimeError, match="envelope was exceeded"):
        gate.evaluate()


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_capacity_rejects_non_finite_measurements(value: float) -> None:
    with pytest.raises(ValueError, match="capacity observation"):
        CapacityObservation(value, 1.0, 2.0, 1)


def test_postgres_ledger_calls_transactional_procedures_without_owning_commit() -> None:
    connection = Connection()
    ledger = PostgresQuotaLedger(connection)
    reservation_id = uuid4()
    actual = ledger.reserve(request(reservation_id=reservation_id))
    assert actual == reservation_id
    assert ledger.settle(
        tenant_id=TENANT_ID,
        reservation_id=reservation_id,
        actual=QuotaSettlement(1, 80, 0.8, {"provider": "unit-test"}),
    ) == "settled"
    assert ledger.release(
        tenant_id=TENANT_ID,
        reservation_id=reservation_id,
        reason="cancelled-before-side-effect",
    ) is True
    assert len(connection.queries) == 3
    assert all("platform." in query for query, _ in connection.queries)
    assert connection.committed is False
    assert connection.closed is False


def test_postgres_ledger_rejects_autocommit_without_active_transaction() -> None:
    ledger = PostgresQuotaLedger(Connection(autocommit=True))
    with pytest.raises(RuntimeError, match="caller-owned active transaction"):
        ledger.reserve(request())


def test_p8_migration_has_transactional_limits_rls_and_append_only_ledger() -> None:
    migration = (
        ROOT / "database/migrations/010_p8_budget_quota_ledger.sql"
    ).read_text(encoding="utf-8")
    for required in (
        "platform.tenant_budget_limits",
        "platform.organization_budget_limits",
        "platform.quota_reservations",
        "platform.quota_ledger",
        "FOR UPDATE",
        "platform.reserve_quota",
        "platform.settle_quota",
        "platform.release_quota",
        "ENABLE ROW LEVEL SECURITY",
        "REVOKE UPDATE, DELETE ON platform.quota_ledger",
    ):
        assert required.lower() in migration.lower()


def test_postgres_ledger_distinguishes_overrun_from_idempotent_settlement() -> None:
    ledger = PostgresQuotaLedger(Connection(result="overrun"))
    assert ledger.settle(
        tenant_id=TENANT_ID,
        reservation_id=uuid4(),
        actual=QuotaSettlement(2, 200, 3.5, {"measurement_ref": "usage:123"}),
    ) == "overrun"

    replay = PostgresQuotaLedger(Connection(result="already_settled"))
    assert replay.settle(
        tenant_id=TENANT_ID,
        reservation_id=uuid4(),
        actual=QuotaSettlement(2, 200, 3.5, {}),
    ) == "already_settled"


def test_capacity_rejects_boolean_and_non_numeric_measurements() -> None:
    with pytest.raises(ValueError, match="capacity envelope"):
        CapacityEnvelope(True, 1.0, 2.0, 1)
    with pytest.raises(ValueError, match="capacity observation"):
        CapacityObservation("not-a-number", 1.0, 2.0, 1)


def test_budget_state_is_not_consumed_when_quota_settlement_fails() -> None:
    from tinlance_agent_platform_contracts import Budget

    budget = Budget(uuid4(), "tenant-a", uuid4(), 10, 60.0, 3)
    quota = TenantQuotaService(
        max_concurrency=1, max_tool_calls=3, max_token_units=100, max_cost_units=10.0
    )
    service = BudgetService(budget, tenant_quota=quota)
    scope = BudgetScope("tenant-a", uuid4(), budget.run_id, "invoice.refund", "invoice:123")
    reservation = service.reserve_scoped(scope, tool_calls=1, seconds=5.0)

    def fail_settlement(_reservation) -> None:
        raise KeyError("simulated quota ledger conflict")

    quota.settle = fail_settlement
    with pytest.raises(KeyError, match="simulated quota ledger conflict"):
        service.consume(reservation, elapsed_seconds=1.0)
    assert service.budget.consumed_tool_calls == 0
    assert reservation.reservation_id in service._reservations
