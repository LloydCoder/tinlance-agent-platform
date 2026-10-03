import pytest

from tinlance_agent_platform_operations import ReleaseGate, ReleaseManifest, UpgradePlan


def test_release_gate_requires_provenance_and_rollback_plan() -> None:
    manifest = ReleaseManifest(
        "v1.2.0",
        "a" * 40,
        "sha256:artifact",
        "evidence://sbom/1",
        "evidence://provenance/1",
        "evidence://signature/1",
    )
    gate = ReleaseGate(manifest, UpgradePlan("migration-1", True, "rollback://1"))
    gate.evaluate()


def test_release_manifest_rejects_missing_provenance() -> None:
    with pytest.raises(ValueError):
        ReleaseManifest("v1.2.0", "a" * 40, "plain", "sbom", "provenance", "signature")


def test_release_gate_requires_tag_qualified_version() -> None:
    manifest = ReleaseManifest(
        "1.2.0",
        "a" * 40,
        "sha256:artifact",
        "evidence://sbom/1",
        "evidence://provenance/1",
        "evidence://signature/1",
    )
    with pytest.raises(RuntimeError, match="tag-qualified"):
        ReleaseGate(manifest, UpgradePlan("migration-1", True, "rollback://1")).evaluate()
