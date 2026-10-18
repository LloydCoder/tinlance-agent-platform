from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from tinlance_agent_platform_multi_agent.interoperability import (
    A2AClient,
    AgentCard,
    AgentSkill,
    RemoteDelegation,
    validate_remote_endpoint,
)


class AcceptCardSignature:
    def verify(self, key_id: str, algorithm: str, payload: bytes, signature: str) -> bool:
        return (
            key_id == "trusted-key-1"
            and algorithm == "EdDSA"
            and payload
            and signature == "dmFsaWQtc2lnbmF0dXJl"
        )


class ScopedCredentialProvider:
    def __init__(self) -> None:
        self.issued = []

    def issue(self, delegation: RemoteDelegation) -> str:
        delegation.validate(
            expected_tenant_id=delegation.tenant_id,
            expected_issuer_id=delegation.parent_agent_id,
            expected_audience=delegation.audience,
        )
        self.issued.append(delegation.delegation_id)
        return "short-lived-scoped-token"


class CaptureA2ATransport:
    def __init__(self) -> None:
        self.calls = []

    def post(
        self,
        endpoint: str,
        resolved_addresses: tuple[str, ...],
        bearer_token: str,
        payload,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
        protocol_version: str,
        content_type: str,
    ):
        self.calls.append(
            (
                endpoint,
                resolved_addresses,
                bearer_token,
                timeout_seconds,
                protocol_version,
                content_type,
            )
        )
        return {"task": {"id": "task-1", "status": {"state": "working"}}}


def make_card(
    *,
    agent_id=None,
    endpoint: str = "https://" + "agent.example" + "/a2a",
    signature: str = "dmFsaWQtc2lnbmF0dXJl",
) -> AgentCard:
    skill = AgentSkill("documents.read", "Read documents", frozenset({"documents:read"}))
    return AgentCard(
        agent_id or uuid4(),
        "1.0",
        "remote",
        "Remote agent",
        endpoint,
        (skill,),
        ("bearer",),
        "1.0.0",
        signature,
        "trusted-key-1",
        "EdDSA",
    )


def test_agent_card_requires_https_and_rejects_credential_material() -> None:
    card = make_card()
    card.validate()
    card.verify_signature(AcceptCardSignature())
    with pytest.raises(ValueError):
        make_card(endpoint="http://" + "agent" + ".example" + "/a2a").validate()
    with pytest.raises(ValueError):
        make_card(endpoint="https://user:password@" + "agent" + ".example" + "/a2a").validate()
    with pytest.raises(ValueError):
        make_card(endpoint="https://127.0.0.1/a2a").validate()
    with pytest.raises(ValueError):
        AgentCard(
            card.agent_id,
            card.protocol_version,
            card.name,
            card.description,
            card.endpoint,
            card.skills,
            ("api_key=secret",),
            card.card_version,
        ).validate()
    with pytest.raises(PermissionError, match="signature"):
        make_card(signature="tampered").verify_signature(AcceptCardSignature())


def test_remote_endpoint_validation_blocks_private_dns_and_pins_public_addresses() -> None:
    with pytest.raises(ValueError, match="non-public"):
        validate_remote_endpoint("https://" + "agent.example" + "/a2a", lambda _host: ("10.0.0.7",))
    assert validate_remote_endpoint(
        "https://" + "agent.example" + "/a2a",
        lambda _host: ("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"),
    ) == ("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")
    with pytest.raises(ValueError, match="localhost"):
        validate_remote_endpoint("https://localhost/a2a", lambda _host: ("127.0.0.1",))


def test_a2a_client_requires_scoped_delegation_and_pinned_transport() -> None:
    transport = CaptureA2ATransport()
    credentials = ScopedCredentialProvider()
    client = A2AClient(
        resolver=lambda _host: ("93.184.216.34",),
        transport=transport,
        card_verifier=AcceptCardSignature(),
        credential_provider=credentials,
    )
    parent = uuid4()
    remote = uuid4()
    issued = datetime(2026, 10, 18, 12, 0, tzinfo=UTC)
    delegation = RemoteDelegation.issue(
        tenant_id="tenant-a",
        parent_agent_id=parent,
        remote_agent_id=remote,
        parent_capabilities=frozenset({"documents:read", "documents:write"}),
        requested_capabilities=frozenset({"documents:read"}),
        resource_scope="tenant-a/documents",
        ttl_seconds=60,
        now=issued,
    )
    result = client.send(
        make_card(agent_id=remote),
        delegation,
        {"method": "message/send"},
        expected_tenant_id="tenant-a",
        expected_issuer_id=parent,
        required_capabilities=frozenset({"documents:read"}),
        resource_scope="tenant-a/documents",
        now=issued + timedelta(seconds=1),
    )
    assert result["task"]["id"] == "task-1"
    assert credentials.issued == [delegation.delegation_id]
    assert transport.calls == [
        (
            "https://" + "agent.example" + "/a2a",
            ("93.184.216.34",),
            "short-lived-scoped-token",
            10.0,
            "1.0",
            "application/a2a+json",
        )
    ]
    with pytest.raises(PermissionError, match="capabilities"):
        client.send(
            make_card(agent_id=remote),
            delegation,
            {"method": "message/send"},
            expected_tenant_id="tenant-a",
            expected_issuer_id=parent,
            required_capabilities=frozenset({"documents:admin"}),
            resource_scope="tenant-a/documents",
            now=issued + timedelta(seconds=1),
        )
    with pytest.raises(PermissionError, match="resource scope"):
        client.send(
            make_card(agent_id=remote),
            delegation,
            {"method": "message/send"},
            expected_tenant_id="tenant-a",
            expected_issuer_id=parent,
            required_capabilities=frozenset({"documents:read"}),
            resource_scope="tenant-a/admin",
            now=issued + timedelta(seconds=1),
        )


def test_remote_delegation_is_attenuated_and_expires() -> None:
    parent = uuid4()
    remote = uuid4()
    issued = datetime(2026, 10, 18, 12, 0, tzinfo=UTC)
    delegation = RemoteDelegation.issue(
        tenant_id="tenant-a",
        parent_agent_id=parent,
        remote_agent_id=remote,
        parent_capabilities=frozenset({"documents:read", "documents:write"}),
        requested_capabilities=frozenset({"documents:read"}),
        resource_scope="tenant-a/documents",
        ttl_seconds=60,
        now=issued,
    )
    delegation.validate(
        expected_tenant_id="tenant-a",
        expected_issuer_id=parent,
        expected_audience=str(remote),
        now=issued + timedelta(seconds=59),
    )
    assert delegation.capabilities == frozenset({"documents:read"})
    assert delegation.audience == str(remote)
    with pytest.raises(PermissionError, match="tenant"):
        delegation.validate(
            expected_tenant_id="tenant-b",
            expected_issuer_id=parent,
            expected_audience=str(remote),
            now=issued + timedelta(seconds=1),
        )
    with pytest.raises(PermissionError, match="issuer"):
        delegation.validate(
            expected_tenant_id="tenant-a",
            expected_issuer_id=remote,
            expected_audience=str(remote),
            now=issued + timedelta(seconds=1),
        )
    with pytest.raises(PermissionError, match="audience"):
        replace(delegation, audience=str(parent)).validate(
            expected_tenant_id="tenant-a",
            expected_issuer_id=parent,
            expected_audience=str(remote),
            now=issued + timedelta(seconds=1),
        )
    with pytest.raises(PermissionError, match="expired"):
        delegation.validate(
            expected_tenant_id="tenant-a",
            expected_issuer_id=parent,
            expected_audience=str(remote),
            now=issued + timedelta(seconds=60),
        )
    with pytest.raises(ValueError, match="TTL"):
        RemoteDelegation.issue(
            tenant_id="tenant-a",
            parent_agent_id=parent,
            remote_agent_id=remote,
            parent_capabilities=frozenset({"documents:read"}),
            requested_capabilities=frozenset({"documents:read"}),
            resource_scope="tenant-a/documents",
            ttl_seconds=3601,
            now=issued,
        )
    with pytest.raises(PermissionError):
        RemoteDelegation.issue(
            tenant_id="tenant-a",
            parent_agent_id=parent,
            remote_agent_id=remote,
            parent_capabilities=frozenset({"documents:read"}),
            requested_capabilities=frozenset({"documents:admin"}),
            resource_scope="tenant-a/documents",
            now=issued,
        )
