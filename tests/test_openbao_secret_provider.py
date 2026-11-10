from __future__ import annotations

import io
import json
import ssl
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError
from urllib.request import Request
from uuid import uuid4

import pytest

import tinlance_agent_platform_secrets.openbao as openbao_module
from tinlance_agent_platform_secrets.openbao import OpenBaoSecretProvider
from tinlance_agent_platform_secrets.scoped import (
    ScopedSecretHandle,
    SecretResolutionError,
)


class _Response:
    def __init__(self, payload: object, status: int = 200, url: str = "") -> None:
        self.status = status
        self.url = url
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def geturl(self) -> str:
        return self.url

    def read(self, limit: int = -1) -> bytes:
        return self._body if limit < 0 else self._body[:limit]


def _handle(name: str = "team/model-provider", version: str = "3") -> ScopedSecretHandle:
    now = datetime.now(UTC)
    return ScopedSecretHandle(
        name=name,
        version=version,
        tenant_id="tenant-a",
        principal_id="principal-a",
        agent_id=uuid4(),
        execution_id=uuid4(),
        capability_id="model:invoke",
        purpose="model:invoke",
        audience="https://api.example",
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
    )


def _payload(value: str = "secret-value", version: int = 3) -> dict[str, object]:
    return {
        "data": {
            "data": {"value": value},
            "metadata": {"version": version},
        }
    }


def test_openbao_kv_v2_resolves_exact_version_and_sends_scoped_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    def fake_urlopen(
        request: Request,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> _Response:
        seen["request"] = request
        seen["timeout"] = timeout
        seen["context"] = context
        return _Response(_payload(), url=request.full_url)

    monkeypatch.setattr(openbao_module, "urlopen", fake_urlopen)
    provider = OpenBaoSecretProvider(
        base_url="https://127.0.0.1:8200",
        token_provider=lambda: "test-token",
        mount="secret",
    )

    assert provider.resolve(_handle()) == "secret-value"
    request = seen["request"]
    assert isinstance(request, Request)
    assert request.full_url == (
        "https://127.0.0.1:8200/v1/secret/data/tenants/tenant-a/team/model-provider?version=3"
    )
    assert request.get_method() == "GET"
    assert request.unredirected_hdrs.get("X-vault-token") == "test-token"
    assert "X-vault-token" not in request.headers
    assert request.get_header("Cache-control") == "no-store"
    assert request.get_header("X-vault-request") == "true"
    assert seen["timeout"] == 3.0
    assert isinstance(seen["context"], ssl.SSLContext)
    assert "test-token" not in repr(provider)


@pytest.mark.parametrize(
    "name",
    ["../escape", "/absolute", "team//secret", "team/../secret", "team/%2e%2e/secret", "a?b"],
)
def test_openbao_rejects_path_traversal_and_url_injection(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    called = False

    def forbidden_urlopen(
        request: Request,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> _Response:
        nonlocal called
        called = True
        raise AssertionError("network request must not be attempted")

    monkeypatch.setattr(openbao_module, "urlopen", forbidden_urlopen)
    provider = OpenBaoSecretProvider(
        base_url="https://127.0.0.1:8200",
        token_provider=lambda: "test-token",
    )

    with pytest.raises(SecretResolutionError):
        provider.resolve(_handle(name=name))
    assert called is False


@pytest.mark.parametrize("version", ["", "0", "-1", "1/2", "01", "9999999999"])
def test_openbao_rejects_invalid_secret_versions(version: str) -> None:
    provider = OpenBaoSecretProvider(
        base_url="https://127.0.0.1:8200",
        token_provider=lambda: "test-token",
    )
    with pytest.raises(SecretResolutionError):
        provider.resolve(_handle(version=version))


def test_openbao_requires_tls_except_explicit_loopback_test_mode() -> None:
    with pytest.raises(ValueError):
        OpenBaoSecretProvider(
            base_url="http://127.0.0.1:8200",
            token_provider=lambda: "test-token",
        )

    provider = OpenBaoSecretProvider(
        base_url="http://127.0.0.1:8200",
        token_provider=lambda: "test-token",
        allow_insecure_loopback=True,
    )
    assert provider.base_url == "http://127.0.0.1:8200"

    with pytest.raises(ValueError):
        OpenBaoSecretProvider(
            base_url="http://192.0.2.10:8200",
            token_provider=lambda: "test-token",
            allow_insecure_loopback=True,
        )


def test_openbao_rejects_credentials_in_base_url() -> None:
    with pytest.raises(ValueError):
        OpenBaoSecretProvider(
            base_url="https" + "://" + "user:password@" + "127.0.0.1:8200",
            token_provider=lambda: "test-token",
        )



def test_openbao_rejects_tenant_path_injection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def forbidden_urlopen(
        request: Request,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> _Response:
        nonlocal called
        called = True
        raise AssertionError("network request must not be attempted")

    monkeypatch.setattr(openbao_module, "urlopen", forbidden_urlopen)
    provider = OpenBaoSecretProvider(
        base_url="https://127.0.0.1:8200",
        token_provider=lambda: "test-token",
    )
    with pytest.raises(SecretResolutionError):
        provider.resolve(
            ScopedSecretHandle(
                name="secret",
                version="1",
                tenant_id="../tenant-b",
                principal_id="principal-a",
                agent_id=uuid4(),
                execution_id=uuid4(),
                capability_id="model:invoke",
                purpose="model:invoke",
                audience="https://api.example",
                issued_at=datetime.now(UTC) - timedelta(seconds=1),
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
        )
    assert called is False


def test_openbao_rejects_token_header_injection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def forbidden_urlopen(
        request: Request,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> _Response:
        nonlocal called
        called = True
        raise AssertionError("network request must not be attempted")

    monkeypatch.setattr(openbao_module, "urlopen", forbidden_urlopen)
    provider = OpenBaoSecretProvider(
        base_url="https://127.0.0.1:8200",
        token_provider=lambda: "token\r\nX-Evil: true",
    )

    with pytest.raises(SecretResolutionError):
        provider.resolve(_handle())
    assert called is False


def test_openbao_maps_forbidden_response_without_leaking_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_urlopen(
        request: Request,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> _Response:
        raise HTTPError(
            request.full_url,
            403,
            "Forbidden",
            hdrs=None,
            fp=io.BytesIO(b"do-not-leak-this-secret"),
        )

    monkeypatch.setattr(openbao_module, "urlopen", forbidden_urlopen)
    provider = OpenBaoSecretProvider(
        base_url="https://127.0.0.1:8200",
        token_provider=lambda: "test-token",
    )

    with pytest.raises(PermissionError) as error:
        provider.resolve(_handle())
    assert "do-not-leak-this-secret" not in str(error.value)


def test_openbao_rejects_version_mismatch_and_malformed_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        openbao_module,
        "urlopen",
        lambda request, *, timeout, context: _Response(_payload(version=2), url=request.full_url),
    )
    provider = OpenBaoSecretProvider(
        base_url="https://127.0.0.1:8200",
        token_provider=lambda: "test-token",
    )
    with pytest.raises(SecretResolutionError):
        provider.resolve(_handle(version="3"))

    monkeypatch.setattr(
        openbao_module,
        "urlopen",
        lambda request, *, timeout, context: _Response(
            {"data": {"data": []}}, url=request.full_url
        ),
    )
    with pytest.raises(SecretResolutionError):
        provider.resolve(_handle())



def test_openbao_rejects_redirected_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        openbao_module,
        "urlopen",
        lambda request, *, timeout, context: _Response(
            _payload(), url="https://attacker.example/steal"
        ),
    )
    provider = OpenBaoSecretProvider(
        base_url="https://127.0.0.1:8200",
        token_provider=lambda: "test-token",
    )
    with pytest.raises(SecretResolutionError, match="redirects"):
        provider.resolve(_handle())


def test_openbao_rejects_oversized_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        openbao_module,
        "urlopen",
        lambda request, *, timeout, context: _Response(_payload("x" * 2048), url=request.full_url),
    )
    provider = OpenBaoSecretProvider(
        base_url="https://127.0.0.1:8200",
        token_provider=lambda: "test-token",
        max_response_bytes=1024,
    )
    with pytest.raises(SecretResolutionError):
        provider.resolve(_handle())
