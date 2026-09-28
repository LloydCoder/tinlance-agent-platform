from uuid import uuid4

import pytest

from tinlance_agent_platform_multi_agent import DelegationService


def test_child_authority_is_narrowed() -> None:
    service = DelegationService()
    parent = uuid4()
    child = uuid4()
    delegation = service.delegate("t1", parent, child, frozenset({"read", "write"}), frozenset({"read"}))
    assert delegation.capabilities == frozenset({"read"})


def test_child_cannot_escalate() -> None:
    service = DelegationService()
    with pytest.raises(PermissionError):
        service.delegate("t1", uuid4(), uuid4(), frozenset({"read"}), frozenset({"write"}))
