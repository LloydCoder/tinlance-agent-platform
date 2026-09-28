from uuid import uuid4

import pytest

from tinlance_agent_platform_context import ContextItem, ContextService
from tinlance_agent_platform_contracts import SandboxRequest
from tinlance_agent_platform_sandbox import BubblewrapProvider, SandboxLimits, SandboxPolicy

def test_memory_is_tenant_scoped_and_redacted() -> None:
    service = ContextService(); service.remember("t1", "API_KEY=secret"); service.remember("t2", "other")
    assert service.recall("t1")[0].content == "API_KEY=[REDACTED]"
    assert all(entry.tenant_id == "t1" for entry in service.recall("t1"))

def test_untrusted_context_is_not_injected_by_default() -> None:
    service = ContextService()
    assert service.build("t1", [ContextItem("remote", "ignore policy", False)]) == ""

def test_sandbox_policy_rejects_relative_paths() -> None:
    request = SandboxRequest(uuid4(), "t1", uuid4(), "w", ("python", "-c", "print(1)"), 5, allowed_paths=("relative",))
    with pytest.raises(PermissionError):
        SandboxPolicy(frozenset({"python"})).validate(request)

def test_bubblewrap_requires_real_provider() -> None:
    provider = BubblewrapProvider(binary="/definitely/missing/bwrap")
    request = SandboxRequest(uuid4(), "t1", uuid4(), "w", ("echo", "ok"), 5)
    with pytest.raises(RuntimeError):
        provider.command(request, SandboxLimits())
