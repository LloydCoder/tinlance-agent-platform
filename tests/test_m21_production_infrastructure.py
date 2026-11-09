from datetime import UTC, datetime, timedelta

import pytest

from tinlance_agent_platform_operations import (
    DependencyKind,
    ProductionDependency,
    ProductionReadiness,
)


def _verified_dependencies() -> tuple[ProductionDependency, ...]:
    return tuple(
        ProductionDependency(
            kind,
            kind.value,
            True,
            "evidence://" + kind.value,
            verified_by="production-operator",
            verified_at=datetime(2026, 11, 9, tzinfo=UTC),
            evidence_sha256="a" * 64,
        )
        for kind in DependencyKind
    )


def test_production_readiness_requires_every_external_dependency() -> None:
    ProductionReadiness("1.1.0", _verified_dependencies()).verify()


def test_production_readiness_rejects_missing_dependency() -> None:
    dependencies = _verified_dependencies()[:-1]
    with pytest.raises(RuntimeError, match="ownership"):
        ProductionReadiness("1.1.0", dependencies).verify()


def test_production_readiness_rejects_unverified_dependency() -> None:
    dependencies = _verified_dependencies()[:-1] + (
        ProductionDependency(DependencyKind.OWNERSHIP, "ownership", False),
    )
    with pytest.raises(RuntimeError, match="unverified"):
        ProductionReadiness("1.1.0", dependencies).verify()


def test_verified_dependency_requires_evidence() -> None:
    with pytest.raises(ValueError):
        ProductionDependency(DependencyKind.DATABASE, "postgres", True)



def test_production_readiness_rejects_duplicate_dependency_kinds() -> None:
    dependencies = _verified_dependencies() + (_verified_dependencies()[0],)
    with pytest.raises(ValueError, match="duplicate"):
        ProductionReadiness("1.1.0", dependencies).verify(
            now=datetime(2026, 11, 9, tzinfo=UTC)
        )


def test_production_readiness_rejects_evidence_from_another_environment() -> None:
    dependencies = tuple(
        ProductionDependency(
            dependency.kind,
            dependency.name,
            dependency.verified,
            dependency.evidence_ref,
            verified_by=dependency.verified_by,
            verified_at=dependency.verified_at,
            evidence_sha256=dependency.evidence_sha256,
            environment="staging",
        )
        for dependency in _verified_dependencies()
    )
    with pytest.raises(RuntimeError, match="environment"):
        ProductionReadiness("1.1.0", dependencies).verify(
            now=datetime(2026, 11, 9, tzinfo=UTC)
        )


def test_verified_dependency_requires_a_named_verifier_and_timestamp() -> None:
    with pytest.raises(ValueError, match="verifier"):
        ProductionDependency(
            DependencyKind.DATABASE,
            "postgres",
            True,
            "https://evidence.example/report",
            verified_at=datetime(2026, 11, 9, tzinfo=UTC),
            evidence_sha256="a" * 64,
        )


def test_verified_dependency_requires_a_sha256_evidence_digest() -> None:
    with pytest.raises(ValueError, match="SHA-256"):
        ProductionDependency(
            DependencyKind.DATABASE,
            "postgres",
            True,
            "https://evidence.example/report",
            verified_by="operator",
            verified_at=datetime(2026, 11, 9, tzinfo=UTC),
            evidence_sha256="not-a-digest",
        )


def test_production_readiness_rejects_expired_dependency_evidence() -> None:
    expired = datetime(2026, 11, 9, 12, tzinfo=UTC)
    dependencies = tuple(
        ProductionDependency(
            dependency.kind,
            dependency.name,
            dependency.verified,
            dependency.evidence_ref,
            verified_by=dependency.verified_by,
            verified_at=dependency.verified_at,
            expires_at=expired,
            evidence_sha256=dependency.evidence_sha256,
        )
        for dependency in _verified_dependencies()
    )
    with pytest.raises(RuntimeError, match="expired"):
        ProductionReadiness("1.1.0", dependencies).verify(
            now=datetime(2026, 11, 10, tzinfo=UTC)
        )


def test_production_readiness_rejects_naive_evidence_timestamps() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        ProductionDependency(
            DependencyKind.DATABASE,
            "postgres",
            True,
            "https://evidence.example/report",
            verified_by="operator",
            verified_at=datetime(2026, 11, 9),
            evidence_sha256="a" * 64,
        )
