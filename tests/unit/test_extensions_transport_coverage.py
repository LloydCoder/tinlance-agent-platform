from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from tinlance_agent_platform_mcp.extensions import (
    EXTENSIONS_JOB_CANCEL,
    ExtensionsHTTPResponse,
    ExtensionsHTTPTransport,
    ExtensionsTransportError,
    _UrllibExtensionsHTTPClient,
)
from tinlance_agent_platform_mcp.gateway import ToolScope


class TokenIssuer:
    def __init__(self, token: str = "platform-token") -> None:
        self.token = token
        self.calls: list[dict[str, object]] = []

    def issue_token(self, **kwargs: object) -> str:
        self.calls.append(kwargs)
        return self.token


class HTTPClient:
    def __init__(self, response: ExtensionsHTTPResponse) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []

    def request(self, method: str, url: str, **kwargs: object) -> ExtensionsHTTPResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        return self.response


def _scope(
    *,
    capability: str = "extensions.jobs.cancel",
    resource: str = "extensions://jobs/{job_id}",
    request_id: str = "extensions-request-0001",
) -> ToolScope:
    return ToolScope(
        tenant_id="tenant-a",
        capability=capability,
        resource=resource,
        subject_id="user-a",
        request_id=request_id,
        traceparent="00-" + "a" * 32 + "-" + "b" * 16 + "-01",
        principal_type="user",
    )


@pytest.mark.parametrize(
    "url",
    [
        "ftp://" + "localhost",
        "https://user@localhost",
        "https://user:pass@localhost",
        "https://" + "localhost/path",
        "https://" + "localhost?query=1",
        "https://" + "localhost#fragment",
    ],
)
def test_extensions_transport_rejects_non_origin_base_urls(url: str) -> None:
    with pytest.raises(ValueError, match="origin"):
        ExtensionsHTTPTransport(base_url=url, token_issuer=TokenIssuer())


def test_extensions_transport_allows_explicit_loopback_http_only() -> None:
    transport = ExtensionsHTTPTransport(
        base_url="http://127.0.0.1:8123",
        token_issuer=TokenIssuer(),
        allow_loopback_http=True,
    )
    assert transport is not None


@pytest.mark.parametrize("timeout", [0, -1, 30.1])
def test_extensions_transport_rejects_unbounded_timeouts(timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout"):
        ExtensionsHTTPTransport(
            base_url="https://" + "127.0.0.1",
            token_issuer=TokenIssuer(),
            timeout_seconds=timeout,
        )


def test_extensions_transport_rejects_unknown_tools_and_mismatched_scope() -> None:
    transport = ExtensionsHTTPTransport(
        base_url="https://" + "127.0.0.1",
        token_issuer=TokenIssuer(),
        http_client=HTTPClient(ExtensionsHTTPResponse(200, {}, b"{}")),
    )
    with pytest.raises(LookupError):
        transport.call(
            "extensions_job_delete",
            {"job_id": "a4f6d9e2-1c3b-4a5d-8e7f-9012bc345678"},
            _scope(),
        )
    with pytest.raises(PermissionError):
        transport.call(
            "extensions_job_cancel",
            {"job_id": "a4f6d9e2-1c3b-4a5d-8e7f-9012bc345678"},
            _scope(capability="extensions.jobs.read"),
        )


def test_extensions_transport_rejects_invalid_job_id_and_bad_issuer_token() -> None:
    http = HTTPClient(ExtensionsHTTPResponse(200, {"content-type": "application/json"}, b"{}"))
    transport = ExtensionsHTTPTransport(
        base_url="https://" + "127.0.0.1",
        token_issuer=TokenIssuer(),
        http_client=http,
    )
    with pytest.raises(ValueError):
        transport.call("extensions_job_cancel", {"job_id": "../other-tenant"}, _scope())
    invalid_token_transport = ExtensionsHTTPTransport(
        base_url="https://" + "127.0.0.1",
        token_issuer=TokenIssuer("token with whitespace"),
        http_client=http,
    )
    with pytest.raises(PermissionError):
        invalid_token_transport.call(
            "extensions_job_cancel",
            {"job_id": "a4f6d9e2-1c3b-4a5d-8e7f-9012bc345678"},
            _scope(),
        )
    assert http.calls == []


@pytest.mark.parametrize(
    ("response", "expected", "retryable"),
    [
        (ExtensionsHTTPResponse(503, {}, b""), 503, True),
        (ExtensionsHTTPResponse(404, {}, b""), 404, False),
    ],
)
def test_extensions_transport_classifies_downstream_statuses(
    response: ExtensionsHTTPResponse, expected: int, retryable: bool
) -> None:
    transport = ExtensionsHTTPTransport(
        base_url="https://" + "127.0.0.1",
        token_issuer=TokenIssuer(),
        http_client=HTTPClient(response),
    )
    with pytest.raises(ExtensionsTransportError) as raised:
        transport.call(
            EXTENSIONS_JOB_CANCEL.name,
            {"job_id": "a4f6d9e2-1c3b-4a5d-8e7f-9012bc345678"},
            _scope(),
        )
    assert raised.value.status_code == expected
    assert raised.value.retryable is retryable


@pytest.mark.parametrize(
    "response",
    [
        ExtensionsHTTPResponse(204, {}, b""),
        ExtensionsHTTPResponse(200, {}, b""),
    ],
)
def test_extensions_transport_accepts_empty_success_responses(
    response: ExtensionsHTTPResponse,
) -> None:
    transport = ExtensionsHTTPTransport(
        base_url="https://" + "127.0.0.1",
        token_issuer=TokenIssuer(),
        http_client=HTTPClient(response),
    )
    assert (
        transport.call(
            EXTENSIONS_JOB_CANCEL.name,
            {"job_id": "a4f6d9e2-1c3b-4a5d-8e7f-9012bc345678"},
            _scope(),
        )
        == {}
    )


@pytest.mark.parametrize(
    "response",
    [
        ExtensionsHTTPResponse(200, {"content-type": "text/plain"}, b"{}"),
        ExtensionsHTTPResponse(200, {"content-type": "application/json"}, b"not-json"),
        ExtensionsHTTPResponse(200, {"content-type": "application/json"}, b"[]"),
    ],
)
def test_extensions_transport_rejects_malformed_success_payloads(
    response: ExtensionsHTTPResponse,
) -> None:
    transport = ExtensionsHTTPTransport(
        base_url="https://" + "127.0.0.1",
        token_issuer=TokenIssuer(),
        http_client=HTTPClient(response),
    )
    with pytest.raises(ExtensionsTransportError):
        transport.call(
            EXTENSIONS_JOB_CANCEL.name,
            {"job_id": "a4f6d9e2-1c3b-4a5d-8e7f-9012bc345678"},
            _scope(),
        )


def test_extensions_urllib_client_disables_redirects_and_bounds_response_body() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "https://attacker.invalid")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"payload":"' + b"x" * 128 + b'"}')

        def log_message(self, *_: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        client = _UrllibExtensionsHTTPClient(max_response_bytes=16)
        redirect = client.request(
            "POST", f"{base}/redirect", headers={}, body=None, timeout_seconds=1
        )
        assert redirect.status_code == 302
        with pytest.raises(ExtensionsTransportError):
            client.request("POST", f"{base}/large", headers={}, body=None, timeout_seconds=1)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=1)
