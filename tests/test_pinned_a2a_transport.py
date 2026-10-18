from __future__ import annotations

from typing import Any

import pytest

import tinlance_agent_platform_multi_agent.interoperability as interop


class FakeResponse:
    def __init__(
        self,
        status: int = 200,
        body: bytes = b'{"jsonrpc":"2.0","id":"r1"}',
        content_type: str = "application/a2a+json",
    ) -> None:
        self.status = status
        self._body = body
        self._content_type = content_type
        self.read_limit: int | None = None

    def getheader(self, name: str, default: str = "") -> str:
        if name.lower() == "content-type":
            return self._content_type
        return default

    def read(self, amount: int = -1) -> bytes:
        self.read_limit = amount
        return self._body[:amount]


class FakeConnection:
    calls: list[dict[str, Any]] = []
    response = FakeResponse()

    def __init__(
        self, host: str, port: int, *, timeout: float, context: Any, pinned_address: str
    ) -> None:
        self.calls.append(
            {
                "host": host,
                "port": port,
                "timeout": timeout,
                "context": context,
                "pinned_address": pinned_address,
            }
        )
        self.request_args: tuple[Any, ...] | None = None
        self.closed = False

    def request(self, method: str, target: str, *, body: bytes, headers: dict[str, str]) -> None:
        self.request_args = (method, target, body, headers)

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


def transport_call(
    transport: interop.PinnedHTTPSRemoteAgentTransport,
    *,
    endpoint: str = "https://agent.example/a2a",
    addresses: tuple[str, ...] = ("93.184.216.34",),
    max_response_bytes: int = 1024,
) -> dict[str, object]:
    return dict(
        transport.post(
            endpoint,
            addresses,
            "scoped-credential",
            {"jsonrpc": "2.0", "id": "r1", "method": "message/send"},
            timeout_seconds=3.0,
            max_response_bytes=max_response_bytes,
            protocol_version="1.0",
            content_type="application/a2a+json",
        )
    )


def test_transport_pins_validated_ip_and_preserves_hostname_for_tls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    class FakeSocket:
        def close(self) -> None:
            seen["socket_closed"] = True

    class FakeTLSContext:
        check_hostname = True

        def wrap_socket(self, raw_socket: FakeSocket, *, server_hostname: str) -> FakeSocket:
            seen["server_hostname"] = server_hostname
            return raw_socket

    def fake_create_connection(
        address: tuple[str, int], timeout: float, source_address: object
    ) -> FakeSocket:
        seen["address"] = address
        seen["timeout"] = timeout
        return FakeSocket()

    monkeypatch.setattr(interop.socket, "create_connection", fake_create_connection)
    connection = interop._PinnedHTTPSConnection(
        "agent.example",
        443,
        timeout=4.0,
        context=FakeTLSContext(),  # type: ignore[arg-type]
        pinned_address="93.184.216.34",
    )
    connection.connect()
    assert seen["address"] == ("93.184.216.34", 443)
    assert seen["server_hostname"] == "agent.example"
    connection.close()


def test_transport_sends_scoped_request_to_pinned_destination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeConnection.calls = []
    FakeConnection.response = FakeResponse()
    monkeypatch.setattr(interop, "_PinnedHTTPSConnection", FakeConnection)
    result = transport_call(interop.PinnedHTTPSRemoteAgentTransport())

    assert result == {"jsonrpc": "2.0", "id": "r1"}
    connection = FakeConnection.calls[-1]
    assert connection["host"] == "agent.example"
    assert connection["pinned_address"] == "93.184.216.34"
    assert FakeConnection.response.read_limit == 1025


def test_transport_rejects_non_public_pinned_address_before_network_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_connection(*args: Any, **kwargs: Any) -> None:
        pytest.fail("connection must not be created for a non-public address")

    monkeypatch.setattr(interop, "_PinnedHTTPSConnection", unexpected_connection)
    with pytest.raises(ValueError, match="non-public pinned"):
        transport_call(
            interop.PinnedHTTPSRemoteAgentTransport(),
            addresses=("127.0.0.1",),
        )


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_transport_rejects_redirects_without_following_them(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    FakeConnection.calls = []
    FakeConnection.response = FakeResponse(status=status)
    monkeypatch.setattr(interop, "_PinnedHTTPSConnection", FakeConnection)
    with pytest.raises(ValueError, match=f"HTTP {status}"):
        transport_call(interop.PinnedHTTPSRemoteAgentTransport())
    assert len(FakeConnection.calls) == 1


def test_transport_rejects_wrong_content_type_and_oversized_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeConnection.calls = []
    FakeConnection.response = FakeResponse(content_type="application/json")
    monkeypatch.setattr(interop, "_PinnedHTTPSConnection", FakeConnection)
    with pytest.raises(ValueError, match="unexpected content type"):
        transport_call(interop.PinnedHTTPSRemoteAgentTransport())

    FakeConnection.response = FakeResponse(body=b"x" * 1025)
    with pytest.raises(ValueError, match="exceeds maximum size"):
        transport_call(
            interop.PinnedHTTPSRemoteAgentTransport(),
            max_response_bytes=1024,
        )


def test_transport_rejects_invalid_json_and_endpoint_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeConnection.calls = []
    FakeConnection.response = FakeResponse(body=b"not-json")
    monkeypatch.setattr(interop, "_PinnedHTTPSConnection", FakeConnection)
    with pytest.raises(ValueError, match="invalid JSON"):
        transport_call(interop.PinnedHTTPSRemoteAgentTransport())

    with pytest.raises(ValueError, match="query parameters"):
        transport_call(
            interop.PinnedHTTPSRemoteAgentTransport(),
            endpoint="https://agent.example/a2a?token=unsafe",
        )


def test_transport_rejects_unsupported_protocol_and_media_type() -> None:
    transport = interop.PinnedHTTPSRemoteAgentTransport()
    with pytest.raises(ValueError, match="wire protocol"):
        transport.post(
            "https://agent.example/a2a",
            ("93.184.216.34",),
            "scoped-credential",
            {"jsonrpc": "2.0"},
            timeout_seconds=3.0,
            max_response_bytes=1024,
            protocol_version="0.9",
            content_type="application/a2a+json",
        )
    with pytest.raises(ValueError, match="content-type"):
        transport.post(
            "https://agent.example/a2a",
            ("93.184.216.34",),
            "scoped-credential",
            {"jsonrpc": "2.0"},
            timeout_seconds=3.0,
            max_response_bytes=1024,
            protocol_version="1.0",
            content_type="application/json",
        )


def test_transport_rejects_header_injection_and_non_string_json_keys() -> None:
    transport = interop.PinnedHTTPSRemoteAgentTransport()
    with pytest.raises(ValueError, match="credential is invalid"):
        transport.post(
            "https://agent.example/a2a",
            ("93.184.216.34",),
            "bad\\nAuthorization: Bearer attacker",
            {"jsonrpc": "2.0"},
            timeout_seconds=3.0,
            max_response_bytes=1024,
            protocol_version="1.0",
            content_type="application/a2a+json",
        )
    with pytest.raises(ValueError, match="object keys must be strings"):
        transport.post(
            "https://agent.example/a2a",
            ("93.184.216.34",),
            "scoped-credential",
            {1: "not-a-json-object-key"},  # type: ignore[dict-item]
            timeout_seconds=3.0,
            max_response_bytes=1024,
            protocol_version="1.0",
            content_type="application/a2a+json",
        )


@pytest.mark.parametrize(
    ("timeout_seconds", "max_response_bytes"),
    [(0.0, 1024), (31.0, 1024), (float("nan"), 1024), (3.0, 0), (3.0, 1_048_577)],
)
def test_transport_rejects_unbounded_timeout_or_response_limit(
    timeout_seconds: float,
    max_response_bytes: int,
) -> None:
    with pytest.raises(ValueError):
        interop.PinnedHTTPSRemoteAgentTransport().post(
            "https://agent.example/a2a",
            ("93.184.216.34",),
            "scoped-credential",
            {"jsonrpc": "2.0"},
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            protocol_version="1.0",
            content_type="application/a2a+json",
        )


def test_transport_rejects_empty_or_invalid_pinned_addresses() -> None:
    transport = interop.PinnedHTTPSRemoteAgentTransport()
    with pytest.raises(ValueError, match="validated destination"):
        transport_call(transport, addresses=())
    with pytest.raises(ValueError, match="invalid pinned address"):
        transport_call(transport, addresses=("not-an-ip",))


def test_transport_rejects_oversized_request_and_non_object_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = interop.PinnedHTTPSRemoteAgentTransport()
    with pytest.raises(ValueError, match="request exceeds maximum size"):
        transport.post(
            "https://agent.example/a2a",
            ("93.184.216.34",),
            "scoped-credential",
            {"payload": "x" * 1_048_577},
            timeout_seconds=3.0,
            max_response_bytes=1024,
            protocol_version="1.0",
            content_type="application/a2a+json",
        )

    FakeConnection.response = FakeResponse(body=b"[]")
    monkeypatch.setattr(interop, "_PinnedHTTPSConnection", FakeConnection)
    with pytest.raises(ValueError, match="must be a JSON object"):
        transport_call(transport)


def test_transport_sanitizes_network_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class FailingConnection(FakeConnection):
        def getresponse(self) -> FakeResponse:
            raise OSError("sensitive internal network detail")

    monkeypatch.setattr(interop, "_PinnedHTTPSConnection", FailingConnection)
    with pytest.raises(RuntimeError, match="remote A2A transport failed") as error:
        transport_call(interop.PinnedHTTPSRemoteAgentTransport())
    assert "sensitive internal network detail" not in str(error.value)
