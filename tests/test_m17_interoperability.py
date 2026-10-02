from uuid import uuid4

import pytest

from tinlance_agent_platform_multi_agent.interoperability import (
    AgentCard,
    AgentSkill,
    RemoteDelegation,
)


def test_agent_card_requires_https_and_rejects_credential_material() -> None:
    skill = AgentSkill("documents.read", "Read documents", frozenset({"documents:read"}))
    card = AgentCard(
        uuid4(), "1.0", "remote", "Remote agent", "https://agent.example/a2a",
        (skill,), ("oauth2",), "7", "signed-card",
    )
    card.validate()
    with pytest.raises(ValueError):
        AgentCard(
            card.agent_id, card.protocol_version, card.name, card.description,
            "http://agent.example/a2a", card.skills, card.authentication_schemes,
            card.card_version,
        ).validate()
    with pytest.raises(ValueError):
        AgentCard(
            card.agent_id, card.protocol_version, card.name, card.description,
            card.endpoint, card.skills, ("api_key=secret",), card.card_version,
        ).validate()


def test_remote_delegation_can_only_attenuate_authority() -> None:
    parent = uuid4()
    remote = uuid4()
    delegation = RemoteDelegation.issue(
        tenant_id="tenant-a",
        parent_agent_id=parent,
        remote_agent_id=remote,
        parent_capabilities=frozenset({"documents:read", "documents:write"}),
        requested_capabilities=frozenset({"documents:read"}),
        resource_scope="tenant-a/documents",
    )
    assert delegation.capabilities == frozenset({"documents:read"})
    with pytest.raises(PermissionError):
        RemoteDelegation.issue(
            tenant_id="tenant-a", parent_agent_id=parent, remote_agent_id=remote,
            parent_capabilities=frozenset({"documents:read"}),
            requested_capabilities=frozenset({"documents:admin"}),
            resource_scope="tenant-a/documents",
        )
