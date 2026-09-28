from uuid import uuid4

import pytest

from tinlance_agent_platform_contracts import SandboxRequest
from tinlance_agent_platform_sandbox import BubblewrapProvider, SandboxLimits


def test_bubblewrap_provider_fails_closed_when_missing() -> None:
    provider = BubblewrapProvider("definitely-not-installed")
    assert not provider.available()
    request = SandboxRequest(uuid4(), "tenant", uuid4(), "workspace", ("true",), 5)
    with pytest.raises(RuntimeError):
        provider.command(request, SandboxLimits())
