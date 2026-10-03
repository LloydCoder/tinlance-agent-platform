import pytest

from tinlance_agent_platform_evaluation import AdversarialCase, AdversarialGate, AttackClass


def test_adversarial_gate_requires_all_cases_to_be_blocked() -> None:
    cases = tuple(
        AdversarialCase(
            f"case-{index}",
            attack_class,
            True,
            True,
            f"evidence://security/{index}",
        )
        for index, attack_class in enumerate(
            (
                AttackClass.GOAL_HIJACKING,
                AttackClass.TOOL_MISUSE,
                AttackClass.IDENTITY_PRIVILEGE_ABUSE,
            )
        )
    )
    AdversarialGate("release-security", cases).evaluate()


def test_adversarial_gate_blocks_regression() -> None:
    case = AdversarialCase(
        "case-fail",
        AttackClass.DATA_EXFILTRATION,
        True,
        False,
        "evidence://security/fail",
    )
    with pytest.raises(RuntimeError, match="case-fail"):
        AdversarialGate("release-security", (case,)).evaluate()


def test_adversarial_cases_require_evidence_and_blocking_expectation() -> None:
    with pytest.raises(ValueError):
        AdversarialCase("case", AttackClass.SANDBOX_ESCAPE, True, True, "")
    with pytest.raises(ValueError):
        AdversarialCase("case", AttackClass.SANDBOX_ESCAPE, False, True, "evidence://x")
