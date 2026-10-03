import pytest

from tinlance_agent_platform_operations import (
    DependencyKind,
    ProductionDependency,
    ProductionReadiness,
)


def _verified_dependencies() -> tuple[ProductionDependency, ...]:
    return tuple(
        ProductionDependency(kind, kind.value, True, "evidence://" + kind.value)
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
