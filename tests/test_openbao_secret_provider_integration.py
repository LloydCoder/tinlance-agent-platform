from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from tinlance_agent_platform_secrets.openbao import OpenBaoSecretProvider
from tinlance_agent_platform_secrets.scoped import ScopedSecretBroker, ScopedSecretHandle


def _test_configuration() -> tuple[str, str]:
    address = os.environ.get("OPENBAO_TEST_ADDR")
    token = os.environ.get("OPENBAO_TEST_TOKEN")
    if not address or not token:
        pytest.skip("OpenBao integration service is not configured")
    return address, token


def _handle(version: str, tenant_id: str = "tenant-a") -> ScopedSecretHandle:
    now = datetime.now(UTC)
    return ScopedSecretHandle(
        name="fcp03/integration",
        version=version,
        tenant_id=tenant_id,
        principal_id="ci-principal",
        agent_id=uuid4(),
        execution_id=uuid4(),
        capability_id="secret:read",
        purpose="integration-test",
        audience="tinlance-fcp03-openbao-ci",
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=2),
    )


def _resolve(broker: ScopedSecretBroker, handle: ScopedSecretHandle) -> str:
    return broker.resolve_for_execution(
        handle,
        tenant_id=handle.tenant_id,
        principal_id=handle.principal_id,
        agent_id=handle.agent_id,
        execution_id=handle.execution_id,
        capability_id=handle.capability_id,
        purpose=handle.purpose,
        audience=handle.audience,
        now=datetime.now(UTC),
    )


def test_openbao_kv_v2_reads_pinned_versions_through_scoped_broker() -> None:
    address, token = _test_configuration()
    provider = OpenBaoSecretProvider(
        base_url=address,
        token_provider=lambda: token,
        allow_insecure_loopback=True,
    )
    broker = ScopedSecretBroker(provider)

    assert _resolve(broker, _handle("1")) == "version-one"
    assert _resolve(broker, _handle("2")) == "version-two"


def test_openbao_token_policy_denies_another_tenant() -> None:
    address, token = _test_configuration()
    provider = OpenBaoSecretProvider(
        base_url=address,
        token_provider=lambda: token,
        allow_insecure_loopback=True,
    )
    broker = ScopedSecretBroker(provider)
    handle = _handle("1", tenant_id="tenant-b")

    with pytest.raises(PermissionError):
        _resolve(broker, handle)


def test_openbao_scoped_broker_rejects_cross_tenant_context() -> None:
    address, token = _test_configuration()
    provider = OpenBaoSecretProvider(
        base_url=address,
        token_provider=lambda: token,
        allow_insecure_loopback=True,
    )
    broker = ScopedSecretBroker(provider)
    handle = _handle("1")

    with pytest.raises(PermissionError):
        broker.resolve_for_execution(
            handle,
            tenant_id="tenant-b",
            principal_id=handle.principal_id,
            agent_id=handle.agent_id,
            execution_id=handle.execution_id,
            capability_id=handle.capability_id,
            purpose=handle.purpose,
            audience=handle.audience,
            now=datetime.now(UTC),
        )
