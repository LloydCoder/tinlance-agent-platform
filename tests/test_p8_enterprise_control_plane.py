from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_enterprise_control_plane_surfaces_exist() -> None:
    required = (
        "database/migrations/001_control_plane.sql",
        "database/migrations/003_m1_runs_approvals.sql",
        "database/migrations/005_m4_governance.sql",
        "database/migrations/009_approval_expiry.sql",
        "packages/tenancy/src/tinlance_agent_platform_tenancy/service.py",
        "packages/approvals/src/tinlance_agent_platform_approvals/service.py",
        "packages/budgets/src/tinlance_agent_platform_budgets/service.py",
        "packages/governance/src/tinlance_agent_platform_governance/service.py",
        "packages/compliance/src/tinlance_agent_platform_compliance/mapping.py",
        "packages/control/src/tinlance_agent_platform_control/hooks.py",
    )
    for relative in required:
        assert (ROOT / relative).exists(), relative


def test_enterprise_control_plane_keeps_authority_at_platform() -> None:
    architecture = (ROOT / "docs/ARCHITECTURE.md").read_text(encoding="utf-8")
    assert "Agent Platform owns" in architecture
    assert "Agentic OS owns" in architecture
    assert "sole authority" in architecture.lower() or "authority" in architecture.lower()
