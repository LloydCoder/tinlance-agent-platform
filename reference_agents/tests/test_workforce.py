from tinlance_reference_agents.workforce import get_reference_workforce


def test_reference_workforce_covers_enterprise_functions() -> None:
    expected = {
        "Executive", "Research", "Finance", "Security", "Engineering", "Sales",
        "Marketing", "Operations", "Customer Success", "Procurement", "Compliance",
    }
    roles = get_reference_workforce()
    assert {role.function for role in roles} == expected
    assert len(roles) == len(expected)
    assert all(role.capabilities and role.escalation_target for role in roles)


def test_reference_workforce_is_not_authority() -> None:
    assert all(not hasattr(role, "authorize") for role in get_reference_workforce())
