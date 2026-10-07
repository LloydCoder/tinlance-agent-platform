import pytest

from tinlance_reference_agents.workforce import (
    REFERENCE_WORKFORCE,
    WorkforceRole,
    get_reference_workforce,
)


def test_reference_workforce_covers_enterprise_functions() -> None:
    expected = {
        "Executive",
        "Research",
        "Finance",
        "Security",
        "Engineering",
        "Sales",
        "Marketing",
        "Operations",
        "Customer Success",
        "Procurement",
        "Compliance",
    }
    roles = get_reference_workforce()
    assert {role.function for role in roles} == expected
    assert len(roles) == len(expected)
    assert all(role.capabilities and role.escalation_target for role in roles)


def test_reference_workforce_has_stable_unique_ids_and_capabilities() -> None:
    roles = get_reference_workforce()
    assert [role.role_id for role in roles] == sorted(role.role_id for role in roles)
    assert len({role.role_id for role in roles}) == len(roles)
    assert all(len(role.capabilities) == len(set(role.capabilities)) for role in roles)


def test_reference_workforce_is_not_authority() -> None:
    assert all(not hasattr(role, "authorize") for role in REFERENCE_WORKFORCE)
    assert all("policy" not in role.as_dict() for role in REFERENCE_WORKFORCE)


def test_reference_workforce_lookup_is_deterministic() -> None:
    assert get_reference_workforce(" security ") is get_reference_workforce("security")
    assert get_reference_workforce("security").role_id == "security"


@pytest.mark.parametrize(
    "role_id",
    ["", "Security", "security role", "security_", "-security", "security-"],
)
def test_invalid_role_id_is_rejected(role_id: str) -> None:
    with pytest.raises(ValueError):
        WorkforceRole(role_id, "Security", "mission", ("security",), "human-ciso")


def test_duplicate_capabilities_are_rejected() -> None:
    with pytest.raises(ValueError, match="unique"):
        WorkforceRole(
            "security",
            "Security",
            "mission",
            ("security", "security"),
            "human-ciso",
        )


def test_role_text_is_normalized_without_mutating_the_catalog() -> None:
    role = WorkforceRole(
        " security ",
        " Security ",
        " Detect and respond ",
        (" security ", "incident-response"),
        " human-ciso ",
    )
    assert role.role_id == "security"
    assert role.function == "Security"
    assert role.mission == "Detect and respond"
    assert role.capabilities == ("security", "incident-response")
    assert role.escalation_target == "human-ciso"
    assert get_reference_workforce() == REFERENCE_WORKFORCE
