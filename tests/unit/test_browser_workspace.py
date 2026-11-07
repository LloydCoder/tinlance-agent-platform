from __future__ import annotations

import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from tinlance_agent_platform_sandbox.browser import (
    BrowserIsolationError,
    BrowserProfileLease,
    BrowserSession,
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
    assert (reopened.profile_path / "persistent-marker").read_text(encoding="utf-8") == "survives-close"
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
