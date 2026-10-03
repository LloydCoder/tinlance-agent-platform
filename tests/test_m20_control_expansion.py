from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from tinlance_agent_platform_attestation import Attestation, AttestationType
from tinlance_agent_platform_compliance import ControlMapping
from tinlance_agent_platform_control import ControlDecision, ControlEvent, enforce_control
from tinlance_agent_platform_crypto import KeyRef, SignatureEnvelope
from tinlance_agent_platform_registry import ResourceKind, ResourceRecord, ResourceState
from tinlance_agent_platform_risk import ActionRisk, RiskAssessment, RiskFactor


def test_risk_is_classification_not_authority() -> None:
    assessment = RiskAssessment(
        "payments.refund",
        ActionRisk.FINANCIAL,
        frozenset({RiskFactor.FINANCIAL_IMPACT}),
        "financial side effect",
    )
    assessment.validate_authority_neutral()
    assert assessment.requires_explicit_approval


def test_risk_requires_normalized_reason_and_action() -> None:
    with pytest.raises(ValueError):
        RiskAssessment("", ActionRisk.READ_ONLY, frozenset(), "reason")
    with pytest.raises(ValueError):
        RiskAssessment("read", ActionRisk.READ_ONLY, frozenset(), "")


def test_control_hooks_fail_closed_and_allow_is_non_authorizing() -> None:
    event = ControlEvent("before_tool_call", "tenant-a", "execution-a", "tool.write")
    assert event.tenant_id == "tenant-a"
    enforce_control(ControlDecision.ALLOW)
    with pytest.raises(PermissionError):
        enforce_control(ControlDecision.DENY)
    with pytest.raises(PermissionError):
        enforce_control(ControlDecision.REQUIRE_REVIEW)
    with pytest.raises(ValueError):
        ControlEvent("", "tenant-a", "execution-a", "tool.write")


def test_registry_is_tenant_bound_and_revocation_is_non_executable() -> None:
    record = ResourceRecord(
        uuid4(), "tenant-a", ResourceKind.TOOL, "billing", "1.2.0", owner="security"
    )
    record.assert_tenant("tenant-a")
    assert record.executable
    revoked = ResourceRecord(
        uuid4(),
        "tenant-a",
        ResourceKind.TOOL,
        "billing",
        "1.2.0",
        ResourceState.REVOKED,
        owner="security",
    )
    assert not revoked.executable
    with pytest.raises(PermissionError):
        record.assert_tenant("tenant-b")
    with pytest.raises(ValueError):
        ResourceRecord(uuid4(), "tenant-a", ResourceKind.TOOL, "billing", "", owner="security")


def test_attestation_requires_validity_and_algorithm_qualified_digest() -> None:
    now = datetime.now(UTC)
    attestation = Attestation(
        "agent-1",
        AttestationType.AGENT,
        "issuer-1",
        "sha256:abc",
        now - timedelta(seconds=1),
        now + timedelta(minutes=5),
        "nonce-1",
    )
    attestation.validate(now=now)
    with pytest.raises(ValueError):
        Attestation(
            "agent-1",
            AttestationType.AGENT,
            "issuer-1",
            "plain",
            now - timedelta(seconds=1),
            now + timedelta(minutes=5),
            "nonce-1",
        ).validate(now=now)
    with pytest.raises(PermissionError):
        Attestation(
            "agent-1",
            AttestationType.AGENT,
            "issuer-1",
            "sha256:abc",
            now - timedelta(minutes=5),
            now - timedelta(seconds=1),
            "nonce-1",
        ).validate(now=now)


def test_crypto_contract_keeps_key_material_outside_platform() -> None:
    envelope = SignatureEnvelope(KeyRef("kms/key", "7", "EdDSA"), "sha256:abc", "sig")
    envelope.validate_digest()
    with pytest.raises(ValueError):
        SignatureEnvelope(KeyRef("kms/key", "7", "EdDSA"), "", "sig")
    with pytest.raises(ValueError):
        SignatureEnvelope(KeyRef("kms/key", "7", "EdDSA"), "plain", "sig").validate_digest()


def test_compliance_mapping_requires_traceability() -> None:
    mapping = ControlMapping(
        "AUTH-001",
        "packages/authorization",
        "tests/test_authorization.py",
        "evidence://ci/auth-001",
        "security",
        ("NIST", "SOC2"),
    )
    mapping.validate()
    ControlMapping(
        "AUTH-002",
        "packages/authorization",
        "tests/test_authorization.py",
        "external://audit/auth-002",
        "security",
    ).validate()
    with pytest.raises(ValueError):
        ControlMapping("AUTH-003", "", "test", "evidence://x", "security")
