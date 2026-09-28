import pytest

from tinlance_agent_platform_sandbox import BubblewrapProvider, SandboxLimits


def test_bubblewrap_provider_fails_closed_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = BubblewrapProvider("definitely-not-installed")
    assert not provider.available()
    with pytest.raises(RuntimeError):
        provider.command(["true"], SandboxLimits())
