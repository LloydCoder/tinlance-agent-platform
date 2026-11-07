from __future__ import annotations

from pathlib import Path

import pytest

from scripts.smoke_browser_environment import build_child_environment


def test_browser_child_environment_is_explicitly_allowlisted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("PYTHONPATH", "/workspace/packages")
    monkeypatch.setenv("LD_LIBRARY_PATH", "/opt/python/lib")
    monkeypatch.setenv("LANG", "C.UTF-8")
    monkeypatch.setenv("LC_ALL", "C.UTF-8")
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", "/runner/browser-cache")
    monkeypatch.setenv("GITHUB_TOKEN", "github-secret")
    monkeypatch.setenv("ACTIONS_RUNTIME_TOKEN", "actions-secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
    monkeypatch.setenv("TINLANCE_TEST_SECRET", "application-secret")

    environment = build_child_environment(
        home=tmp_path / "home",
        tmpdir=tmp_path / "tmp",
        include_playwright=True,
    )

    assert environment == {
        "PATH": "/usr/bin",
        "PYTHONPATH": "/workspace/packages",
        "LD_LIBRARY_PATH": "/opt/python/lib",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PLAYWRIGHT_BROWSERS_PATH": "/runner/browser-cache",
        "HOME": str(tmp_path / "home"),
        "TMPDIR": str(tmp_path / "tmp"),
        "XDG_CONFIG_HOME": str(tmp_path / "home" / ".config"),
        "XDG_CACHE_HOME": str(tmp_path / "home" / ".cache"),
    }
    assert not any(
        key.startswith(("GITHUB_", "ACTIONS_", "AWS_")) or "SECRET" in key
        for key in environment
    )


def test_proxy_child_environment_does_not_include_browser_cache(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", "/runner/browser-cache")

    environment = build_child_environment(
        home=tmp_path / "proxy-home",
        tmpdir=tmp_path / "proxy-tmp",
    )

    assert environment["HOME"] == str(tmp_path / "proxy-home")
    assert environment["TMPDIR"] == str(tmp_path / "proxy-tmp")
    assert "PLAYWRIGHT_BROWSERS_PATH" not in environment
