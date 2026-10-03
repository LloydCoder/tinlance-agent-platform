from datetime import UTC, datetime, timedelta

import pytest

from tinlance_agent_platform_attestation import AttestationTrust, RevocationRecord
from tinlance_agent_platform_crypto import KeyLifecycle, KeyState, KeyVersion
from tinlance_agent_platform_identity import TokenSecurityContext


def test_token_security_enforces_issuer_audience_nonce_and_time() -> None:
    now = datetime.now(UTC)
    token = TokenSecurityContext(
        "https://issuer.example",
        ("api://platform",),
        "agent-1",
        "jti-1",
        now - timedelta(seconds=1),
        now + timedelta(minutes=5),
        nonce="nonce-1",
        sender_key_thumbprint="thumbprint",
    )
    token.validate(
        expected_issuer="https://issuer.example",
        expected_audience="api://platform",
        expected_nonce="nonce-1",
        now=now,
    )
    with pytest.raises(PermissionError):
        token.validate(
            expected_issuer="https://other.example",
            expected_audience="api://platform",
            now=now,
        )
    with pytest.raises(PermissionError):
        token.validate(
            expected_issuer="https://issuer.example",
            expected_audience="api://platform",
            expected_nonce="wrong",
            now=now,
        )


def test_key_lifecycle_requires_one_active_version() -> None:
    now = datetime.now(UTC)
    active = KeyVersion(
        "kms/platform",
        "2",
        "EdDSA",
        KeyState.ACTIVE,
        now - timedelta(seconds=1),
    )
    retired = KeyVersion(
        "kms/platform",
        "1",
        "EdDSA",
        KeyState.RETIRED,
        now - timedelta(days=1),
        now - timedelta(hours=1),
    )
    assert active.usable(now=now)
    assert KeyLifecycle((retired, active)).active() is active
    with pytest.raises(RuntimeError):
        KeyLifecycle((retired,)).active()


def test_revocation_and_attestation_expiry_are_fail_closed() -> None:
    now = datetime.now(UTC)
    record = RevocationRecord("att-1", "revoked", now)
    assert record.attestation_id == "att-1"
    assert AttestationTrust("att-1", now + timedelta(minutes=5)).usable(now=now)
    assert not AttestationTrust("att-1", now + timedelta(minutes=5), True).usable(now=now)
    assert not AttestationTrust("att-1", now - timedelta(seconds=1)).usable(now=now)
    with pytest.raises(ValueError):
        RevocationRecord("", "reason", now)
