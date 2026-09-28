import pytest
from tinlance_agent_platform_operations import Config, OperationsService


def test_production_config_rejects_embedded_password() -> None:
    with pytest.raises(ValueError):
        Config("production", "postgres://host/db?password=secret", "vault").validate()


def test_readiness_is_fail_closed() -> None:
    status = OperationsService().readiness({"database": True, "queue": False})
    assert not status.ready
