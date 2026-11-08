from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from tinlance_agent_platform_sandbox.browser import (
    BrowserIsolationError,
    BrowserProfileLease,
    BrowserSession,
    BrowserWorkspaceManager,
)


def test_profile_is_persistent_and_workspace_scoped(tmp_path: Path) -> None:
    root = tmp_path / "tenant-a"
    first = BrowserProfileLease.acquire(root, "tenant-a", "workspace-1")
    first_path = first.profile_path
    assert stat.S_IMODE(first_path.stat().st_mode) == 0o700
    (first_path / "persistent-marker").write_text("survives-close", encoding="utf-8")
    first.close()

    reopened = BrowserProfileLease.acquire(root, "tenant-a", "workspace-1")
    assert reopened.profile_path == first_path
    marker = (reopened.profile_path / "persistent-marker").read_text(encoding="utf-8")
    assert marker == "survives-close"
    reopened.close()

    other_workspace = BrowserProfileLease.acquire(root, "tenant-a", "workspace-2")
    assert other_workspace.profile_path != first_path
    other_workspace.close()


def test_profile_root_is_bound_to_one_tenant(tmp_path: Path) -> None:
    root = tmp_path / "shared-root"
    lease = BrowserProfileLease.acquire(root, "tenant-a", "workspace-1")
    lease.close()
    with pytest.raises(BrowserIsolationError, match="another tenant"):
        BrowserProfileLease.acquire(root, "tenant-b", "workspace-1")


def test_profile_lock_prevents_concurrent_workspace_sessions(tmp_path: Path) -> None:
    root = tmp_path / "tenant-a"
    first = BrowserProfileLease.acquire(root, "tenant-a", "workspace-1")
    try:
        with pytest.raises(BrowserIsolationError, match="already in use"):
            BrowserProfileLease.acquire(root, "tenant-a", "workspace-1")
    finally:
        first.close()


def test_profile_root_rejects_symlinks_and_relative_paths(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "profile-link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(BrowserIsolationError, match="symlink"):
        BrowserProfileLease.acquire(link, "tenant-a", "workspace-1")
    with pytest.raises(ValueError, match="absolute"):
        BrowserProfileLease.acquire("relative/profile", "tenant-a", "workspace-1")


def test_session_rejects_plain_http_and_url_credentials(tmp_path: Path) -> None:
    lease = BrowserProfileLease.acquire(tmp_path / "tenant-a", "tenant-a", "workspace-1")

    class FakePage:
        def goto(self, *_: object, **__: object) -> None:
            raise AssertionError("invalid URL must be rejected before browser navigation")

    class FakeContext:
        def new_page(self) -> FakePage:
            return FakePage()

        def close(self) -> None:
            return None

    class FakePlaywright:
        def stop(self) -> None:
            return None

    session = BrowserSession(FakePlaywright(), FakeContext(), lease, 1000)
    try:
        with pytest.raises(BrowserIsolationError, match="HTTPS"):
            session.navigate("http://example.com")
        with pytest.raises(BrowserIsolationError, match="HTTPS"):
            session.navigate("https://user:pass@example.com")
    finally:
        session.close()


def test_session_close_is_idempotent(tmp_path: Path) -> None:
    lease = BrowserProfileLease.acquire(tmp_path / "tenant-a", "tenant-a", "workspace-1")
    closed = SimpleNamespace(context=0, playwright=0)

    class FakePage:
        def goto(self, *_: object, **__: object) -> None:
            return None

    class FakeContext:
        def new_page(self) -> FakePage:
            return FakePage()

        def close(self) -> None:
            closed.context += 1

    class FakePlaywright:
        def stop(self) -> None:
            closed.playwright += 1

    session = BrowserSession(FakePlaywright(), FakeContext(), lease, 1000)
    session.close()
    session.close()
    assert closed.context == 1
    assert closed.playwright == 1


def test_workspace_manager_rejects_wrong_tenant_uid(tmp_path: Path) -> None:
    manager = BrowserWorkspaceManager(
        tmp_path / "tenant-a",
        "http://10.253.0.1:3128",
        tenant_id="tenant-a",
        expected_uid=os.geteuid() + 1,
    )
    with pytest.raises(BrowserIsolationError, match="UID"):
        manager.open("workspace-1")


def test_profile_lease_rejects_empty_oversized_and_nul_identifiers(tmp_path: Path) -> None:
    invalid_pairs = [
        ("", "workspace-1"),
        ("tenant-a", ""),
        ("tenant\x00a", "workspace-1"),
        ("tenant-a", "workspace\x00-1"),
        ("t" * 257, "workspace-1"),
        ("tenant-a", "w" * 257),
    ]
    for tenant_id, workspace_id in invalid_pairs:
        with pytest.raises(ValueError, match="identifiers"):
            BrowserProfileLease.acquire(tmp_path / "profiles", tenant_id, workspace_id)


def test_session_exposes_owned_context_and_rejects_nonstandard_https_ports(tmp_path: Path) -> None:
    lease = BrowserProfileLease.acquire(tmp_path / "tenant-a", "tenant-a", "workspace-1")
    navigations: list[str] = []

    class FakePage:
        def goto(self, url: str, **_: object) -> str:
            navigations.append(url)
            return "navigated"

    class FakeContext:
        def new_page(self) -> FakePage:
            return FakePage()

        def close(self) -> None:
            return None

    class FakePlaywright:
        def stop(self) -> None:
            return None

    context = FakeContext()
    session = BrowserSession(FakePlaywright(), context, lease, 1000)
    try:
        assert session.profile_path == lease.profile_path
        assert session.context is context
        assert session.navigate("https://example.com") == "navigated"
        assert navigations == ["https://example.com"]
        with pytest.raises(BrowserIsolationError, match="HTTPS"):
            session.navigate("https://example.com:8443")
        with pytest.raises(BrowserIsolationError, match="empty or too large"):
            session.navigate("https://example.com/" + "x" * 16_384)
    finally:
        session.close()


def test_session_releases_playwright_and_profile_when_context_close_fails(tmp_path: Path) -> None:
    lease = BrowserProfileLease.acquire(tmp_path / "tenant-a", "tenant-a", "workspace-1")
    stopped = SimpleNamespace(value=0)

    class FakePage:
        def goto(self, *_: object, **__: object) -> None:
            return None

    class FakeContext:
        def new_page(self) -> FakePage:
            return FakePage()

        def close(self) -> None:
            raise RuntimeError("context close failed")

    class FakePlaywright:
        def stop(self) -> None:
            stopped.value += 1

    session = BrowserSession(FakePlaywright(), FakeContext(), lease, 1000)
    with pytest.raises(RuntimeError, match="context close failed"):
        session.close()
    assert stopped.value == 1
    with BrowserProfileLease.acquire(tmp_path / "tenant-a", "tenant-a", "workspace-1"):
        pass


def test_workspace_manager_rejects_invalid_tenant_timeout_and_uid(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="tenant identifier"):
        BrowserWorkspaceManager(
            tmp_path / "profiles",
            "http://10.253.0.1:3128",
            tenant_id="",
            expected_uid=1000,
        )
    with pytest.raises(ValueError, match="timeout"):
        BrowserWorkspaceManager(
            tmp_path / "profiles",
            "http://10.253.0.1:3128",
            tenant_id="tenant-a",
            expected_uid=1000,
            navigation_timeout_ms=0,
        )
    with pytest.raises(ValueError, match="non-root"):
        BrowserWorkspaceManager(
            tmp_path / "profiles",
            "http://10.253.0.1:3128",
            tenant_id="tenant-a",
            expected_uid=0,
        )


def test_network_isolation_rejects_root_and_non_ip_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    import tinlance_agent_platform_sandbox.browser as browser_module

    monkeypatch.setattr(browser_module.os, "geteuid", lambda: 0)
    with pytest.raises(BrowserIsolationError, match="non-root"):
        browser_module.verify_browser_network_isolation("http://10.253.0.1:3128")
    monkeypatch.setattr(browser_module.os, "geteuid", lambda: 1000)
    with pytest.raises(BrowserIsolationError, match="IP literal"):
        browser_module.verify_browser_network_isolation("http://proxy.internal:3128")


def test_network_isolation_rejects_missing_route_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tinlance_agent_platform_sandbox.browser as browser_module

    monkeypatch.setattr(browser_module.os, "geteuid", lambda: 1000)
    original_is_file = Path.is_file

    def is_file(path: Path) -> bool:
        if path == Path("/proc/net/route"):
            return False
        return original_is_file(path)

    monkeypatch.setattr(Path, "is_file", is_file)
    with pytest.raises(BrowserIsolationError, match="route table is unavailable"):
        browser_module.verify_browser_network_isolation("http://10.253.0.1:3128")
