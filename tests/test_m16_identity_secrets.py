from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from tinlance_agent_platform_identity.federation import VerifiedAgentIdentity
from tinlance_agent_platform_secrets.scoped import ScopedSecretHandle


def _identity() -> VerifiedAgentIdentity:
    now = datetime.now(UTC)
    return VerifiedAgentIdentity(
        subject_id="agent-1",
        tenant_id="tenant-a",
        issuer="https://issuer.example",
        audience="tinlance-platform",
        scopes=frozenset({"docs:write"}),
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
        token_id="token-1",
    )


def test_verified_identity_requires_exact_issuer_and_audience() -> None:
    identity = _identity()
    identity.validate(
        expected_issuer="https://issuer.example",
        expected_audience="tinlance-platform",
    )
    with pytest.raises(PermissionError):
        identity.validate(
            expected_issuer="https://attacker.example",
            expected_audience="tinlance-platform",
        )


def test_expired_identity_is_rejected() -> None:
    identity = _identity()
    now = identity.expires_at + timedelta(seconds=1)
    with pytest.raises(PermissionError):
        identity.validate(
            expected_issuer=identity.issuer,
            expected_audience=identity.audience,
            now=now,
        )


def test_secret_handle_is_execution_scoped() -> None:
    agent_id = uuid4()
    execution_id = uuid4()
    handle = ScopedSecretHandle(
        "provider-key",
        "7",
        "tenant-a",
        "principal-a",
        agent_id,
        execution_id,
        "docs:write",
        "docs:write",
        "https://api.example",
        datetime.now(UTC) - timedelta(seconds=1),
        datetime.now(UTC) + timedelta(minutes=5),
    )
    handle.validate_scope(
        tenant_id="tenant-a",
        principal_id="principal-a",
        agent_id=agent_id,
        execution_id=execution_id,
        capability_id="docs:write",
        purpose="docs:write",
        audience="https://api.example",
    )
    with pytest.raises(PermissionError):
        handle.validate_scope(
            tenant_id="tenant-b",
            principal_id="principal-a",
            agent_id=agent_id,
            execution_id=execution_id,
            capability_id="docs:write",
            purpose="docs:write",
            audience="https://api.example",
        )


def test_secret_handle_rejects_expiry_and_scope_confusion() -> None:
    agent_id, execution_id = uuid4(), uuid4()
    now = datetime.now(UTC)
    handle = ScopedSecretHandle(
        "key",
        "1",
        "tenant-a",
        "principal-a",
        agent_id,
        execution_id,
        "docs:write",
        "docs:write",
        "https://api.example",
        now - timedelta(minutes=2),
        now - timedelta(minutes=1),
    )
    with pytest.raises(PermissionError):
        handle.validate_scope(
            tenant_id="tenant-a",
            principal_id="principal-a",
            agent_id=agent_id,
            execution_id=execution_id,
            capability_id="docs:write",
            purpose="docs:write",
            audience="https://api.example",
            now=now,
        )
    with pytest.raises(PermissionError):
        handle.validate_scope(
            tenant_id="tenant-a",
            principal_id="principal-a",
            agent_id=agent_id,
            execution_id=execution_id,
            capability_id="docs:write",
            purpose="wrong-purpose",
            audience="https://api.example",
            now=now,
        )
