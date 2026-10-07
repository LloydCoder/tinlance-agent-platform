from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_production_runtime_has_durable_primitives() -> None:
    required = (
        "packages/durability/src/tinlance_agent_platform_durability/leases.py",
        "packages/durability/src/tinlance_agent_platform_durability/outbox.py",
        "packages/events/src/tinlance_agent_platform_events/outbox.py",
        "tests/test_durable_execution.py",
        "docs/production-runtime/M13-1-DURABLE-EXECUTION.md",
    )
    for relative in required:
        assert (ROOT / relative).exists(), relative


def test_production_runtime_keeps_external_infrastructure_explicit() -> None:
    architecture = (ROOT / "docs/ARCHITECTURE.md").read_text(encoding="utf-8").lower()
    assert "postgresql" in architecture
    assert "external secret management" in architecture
    assert "backup/restore" in architecture
    assert "telemetry" in architecture
