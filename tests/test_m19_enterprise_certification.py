import pytest

from tinlance_agent_platform_operations.certification import (
    AcceptanceItem,
    AcceptanceStatus,
    EnterpriseAcceptance,
    production_acceptance_items,
)


def test_default_production_acceptance_is_not_certified_without_operator_evidence() -> None:
    acceptance = EnterpriseAcceptance("1.1.0", production_acceptance_items())
    with pytest.raises(RuntimeError):
        acceptance.certify()


def test_enterprise_acceptance_requires_status_and_evidence() -> None:
    items = tuple(
        AcceptanceItem(
            item.control_id,
            item.description,
            AcceptanceStatus.VERIFIED,
            "evidence://" + item.control_id,
        )
        for item in production_acceptance_items()
    )
    EnterpriseAcceptance("1.1.0", items).certify()


def test_unverified_control_blocks_ga() -> None:
    items = production_acceptance_items()
    items = items[:-1] + (
        AcceptanceItem("ownership", "Security and operational ownership assigned"),
    )
    with pytest.raises(RuntimeError, match="ownership"):
        EnterpriseAcceptance("1.1.0", items).certify()
