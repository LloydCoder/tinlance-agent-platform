from datetime import UTC, datetime, timedelta

import pytest

from tinlance_agent_platform_attestation import AttestationTrust, RevocationRecord
from tinlance_agent_platform_crypto import KeyLifecycle, KeyState, KeyVersion
from tinlance_agent_platform_identity import TokenSecurityContext


def test_token_security_enforces_issuer_audience_nonce_and_time() -> None:
    now = datetime.now(UTC)
    token = TokenSecurityContext(
        "https://issuer.invalid", ("api://platform",), "agent-1", "jti-1",
        now - timedelta(seconds=1), now + timedelta(minutes=5), nonce="nonce-1",
    )
    token.validate(
        expected_issuer="https://issuer.invalid", expected_audience="api://platform",
        expected_nonce="nonce-1", now=now,
    )
    with pytest.raises(PermissionError, match="issuer"):
        token.validate(expected_issuer="https://other.invalid", expected_audience="api://platform", now=now)
    with pytest.raises(PermissionError, match="audience"):
        token.validate(expected_issuer="https://issuer.invalid", expected_audience="api://other", now=now)
    with pytest.raises(PermissionError, match="nonce"):
        token.validate(
            expected_issuer="https://issuer.invalid", expected_audience="api://platform",
            expected_nonce="wrong", now=now,
        )


def test_token_security_rejects_empty_identity_claims_and_audience() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="audience"):
        TokenSecurityContext("https://issuer.invalid", (), "agent", "jti", now, now + timedelta(minutes=1))
    with pytest.raises(ValueError, match="required"):
        TokenSecurityContext("https://issuer.invalid", ("api://platform",), " ", "jti", now, now + timedelta(minutes=1))


def test_token_security_rejects_naive_or_inverted_time_windows() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="timezone-aware"):
        TokenSecurityContext(
            "https://issuer.invalid", ("api://platform",), "agent", "jti",
            datetime(2026, 1, 1), now + timedelta(minutes=1),
        )
    with pytest.raises(ValueError, match="validity"):
        TokenSecurityContext("https://issuer.invalid", ("api://platform",), "agent", "jti", now, now)


def test_token_security_enforces_not_before_and_exact_expiry_boundary() -> None:
    now = datetime.now(UTC)
    token = TokenSecurityContext(
        "https://issuer.invalid", ("api://platform",), "agent", "jti",
        now - timedelta(minutes=1), now + timedelta(minutes=1),
        not_before=now + timedelta(seconds=1),
    )
    with pytest.raises(PermissionError, match="not yet valid"):
        token.validate(expected_issuer="https://issuer.invalid", expected_audience="api://platform", now=now)
    with pytest.raises(PermissionError, match="validity window"):
        token.validate(
            expected_issuer="https://issuer.invalid", expected_audience="api://platform",
            now=now + timedelta(minutes=1),
        )


def test_sender_bound_token_requires_matching_request_key_thumbprint() -> None:
    now = datetime.now(UTC)
    thumbprint = "A" * 43
    token = TokenSecurityContext(
        "https://issuer.invalid", ("api://platform",), "agent", "jti",
        now - timedelta(seconds=1), now + timedelta(minutes=1),
        sender_key_thumbprint=thumbprint,
    )
    with pytest.raises(PermissionError, match="requires request key binding"):
        token.validate(expected_issuer="https://issuer.invalid", expected_audience="api://platform", now=now)
    with pytest.raises(PermissionError, match="sender key"):
        token.validate(
            expected_issuer="https://issuer.invalid", expected_audience="api://platform",
            expected_sender_key_thumbprint="B" * 43, now=now,
        )
    token.validate(
        expected_issuer="https://issuer.invalid", expected_audience="api://platform",
        expected_sender_key_thumbprint=thumbprint, now=now,
    )


def test_sender_key_thumbprint_must_be_canonical_sha256_base64url() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="thumbprint"):
        TokenSecurityContext(
            "https://issuer.invalid", ("api://platform",), "agent", "jti",
            now, now + timedelta(minutes=1), sender_key_thumbprint="not-a-thumbprint",
        )


def test_key_lifecycle_requires_one_active_version_for_one_key() -> None:
    now = datetime.now(UTC)
    active = KeyVersion("kms/platform", "2", "EdDSA", KeyState.ACTIVE, now - timedelta(seconds=1))
    retired = KeyVersion(
        "kms/platform", "1", "EdDSA", KeyState.RETIRED,
        now - timedelta(days=1), now - timedelta(hours=1),
    )
    lifecycle = KeyLifecycle((retired, active))
    assert active.usable(now=now)
    assert lifecycle.active(now=now) is active
    with pytest.raises(RuntimeError, match="exactly one active"):
        KeyLifecycle((retired,)).active(now=now)


def test_key_lifecycle_rejects_multiple_active_versions_and_duplicate_versions() -> None:
    now = datetime.now(UTC)
    first = KeyVersion("kms/platform", "1", "EdDSA", KeyState.ACTIVE, now)
    second = KeyVersion("kms/platform", "2", "EdDSA", KeyState.ACTIVE, now)
    with pytest.raises(RuntimeError, match="exactly one active"):
        KeyLifecycle((first, second)).active(now=now)
    with pytest.raises(ValueError, match="duplicate"):
        KeyLifecycle((first, first))


def test_key_lifecycle_rejects_mixed_key_ids_and_invalid_state_timestamps() -> None:
    now = datetime.now(UTC)
    first = KeyVersion("kms/one", "1", "EdDSA", KeyState.ACTIVE, now)
    second = KeyVersion("kms/two", "1", "EdDSA", KeyState.RETIRED, now, now)
    with pytest.raises(ValueError, match="same key"):
        KeyLifecycle((first, second))
    with pytest.raises(ValueError, match="retirement timestamp"):
        KeyVersion("kms/platform", "1", "EdDSA", KeyState.RETIRED, now)
    with pytest.raises(ValueError, match="revocation timestamp"):
        KeyVersion("kms/platform", "1", "EdDSA", KeyState.REVOKED, now)


def test_key_lifecycle_rejects_naive_timestamps_and_future_activation() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="timezone-aware"):
        KeyVersion("kms/platform", "1", "EdDSA", KeyState.ACTIVE, datetime(2026, 1, 1))
    future = KeyVersion("kms/platform", "1", "EdDSA", KeyState.ACTIVE, now + timedelta(minutes=1))
    assert not future.usable(now=now)


def test_revocation_and_attestation_expiry_are_fail_closed() -> None:
    now = datetime.now(UTC)
    record = RevocationRecord("att-1", "compromised", now)
    assert record.attestation_id == "att-1"
    assert AttestationTrust("att-1", now + timedelta(minutes=5), valid_from=now - timedelta(seconds=1)).usable(now=now)
    assert not AttestationTrust(
        "att-1", now + timedelta(minutes=5), revoked=True, revoked_at=now
    ).usable(now=now)
    assert not AttestationTrust("att-1", now - timedelta(seconds=1)).usable(now=now)
    assert not AttestationTrust(
        "att-1", now + timedelta(minutes=5), valid_from=now + timedelta(seconds=1)
    ).usable(now=now)
    with pytest.raises(ValueError, match="identifier and reason"):
        RevocationRecord(" ", "reason", now)


def test_attestation_trust_rejects_naive_and_inverted_validity_windows() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="timezone-aware"):
        AttestationTrust("att-1", datetime(2026, 1, 1))
    with pytest.raises(ValueError, match="validity"):
        AttestationTrust("att-1", now, valid_from=now + timedelta(seconds=1))
    with pytest.raises(ValueError, match="revocation timestamp"):
        AttestationTrust("att-1", now + timedelta(minutes=1), revoked=True)
