import pytest

from tinlance_agent_platform_registry import Compatibility, ResourceGovernance


def test_registry_governance_requires_provenance_and_digest() -> None:
    governance = ResourceGovernance(
        "billing-tool",
        "2.1.0",
        "sha256:abc",
        "provenance://build/123",
        (Compatibility("mcp", "2026-06-18", "2026-07-28"),),
    )
    governance.assert_usable("mcp", "2026-07-01")
    with pytest.raises(RuntimeError):
        governance.assert_usable("mcp", "2025-01-01")


def test_registry_governance_blocks_revoked_resources() -> None:
    governance = ResourceGovernance(
        "billing-tool",
        "2.1.0",
        "sha256:abc",
        "provenance://build/123",
        (Compatibility("mcp", "2026-06-18"),),
        revoked=True,
    )
    with pytest.raises(PermissionError):
        governance.assert_usable("mcp", "2026-07-01")


def test_registry_compatibility_requires_a_version() -> None:
    compatibility = Compatibility("a2a", "1.0.0")
    assert compatibility.supports("1.1.0")
    with pytest.raises(ValueError):
        compatibility.supports("")
