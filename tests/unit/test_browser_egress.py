from __future__ import annotations

import contextlib
import ipaddress
import socket

import pytest

from tinlance_agent_platform_sandbox.egress_proxy import (
    BrowserEgressProxy,
    EgressDenied,
    EgressPolicy,
    ResolvedTarget,
    connect_pinned_target,
    normalize_hostname,
    resolve_public_target,
)


def policy(domains: frozenset[str] = frozenset({"example.com"})) -> EgressPolicy:
    return EgressPolicy(allowed_domains=domains)


def test_exact_allowlist_and_pinned_public_addresses() -> None:
    result = resolve_public_target(
        "EXAMPLE.COM.",
        443,
        policy(),
        resolver=lambda _: ("93.184.216.34",),
    )
    assert result == ResolvedTarget("example.com", 443, ("93.184.216.34",))


def test_explicit_wildcard_allows_subdomain_but_not_apex() -> None:
    wildcard = policy(frozenset({"*.example.com"}))
    assert (
        resolve_public_target(
            "docs.example.com", 443, wildcard, resolver=lambda _: ("93.184.216.34",)
        ).hostname
        == "docs.example.com"
    )
    with pytest.raises(EgressDenied):
        resolve_public_target("example.com", 443, wildcard, resolver=lambda _: ("93.184.216.34",))


@pytest.mark.parametrize(
    "hostname",
    [
        "not-example.com",
        "localhost",
        "internal.local",
        "metadata.google.internal",
        "127.0.0.1",
        "169.254.169.254",
        "2130706433",
    ],
)
def test_unapproved_or_special_use_hosts_are_rejected(hostname: str) -> None:
    with pytest.raises(EgressDenied):
        resolve_public_target(hostname, 443, policy(), resolver=lambda _: ("93.184.216.34",))


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.169.254",
        "::1",
        "fc00::1",
        "fe80::1",
        "224.0.0.1",
        "0.0.0.0",
        "192.0.2.1",
        "::ffff:127.0.0.1",
    ],
)
def test_non_public_dns_answers_are_rejected(address: str) -> None:
    with pytest.raises(EgressDenied):
        resolve_public_target("example.com", 443, policy(), resolver=lambda _: (address,))


def test_mixed_public_and_private_dns_answers_fail_closed() -> None:
    with pytest.raises(EgressDenied):
        resolve_public_target(
            "example.com",
            443,
            policy(),
            resolver=lambda _: ("93.184.216.34", "169.254.169.254"),
        )


def test_only_https_port_is_allowed() -> None:
    with pytest.raises(EgressDenied):
        resolve_public_target("example.com", 80, policy(), resolver=lambda _: ("93.184.216.34",))


def test_invalid_idna_hostname_is_rejected() -> None:
    with pytest.raises(EgressDenied):
        normalize_hostname("bad..example.com")


def test_connector_uses_validated_ip_literal_without_hostname_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []

    class FakeSocket:
        pass

    def fake_create_connection(address: tuple[object, ...], timeout: float) -> FakeSocket:
        calls.append((address, timeout))
        return FakeSocket()

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    target = ResolvedTarget("example.com", 443, ("93.184.216.34",))
    result = connect_pinned_target(target, timeout_seconds=3.0)

    assert isinstance(result, FakeSocket)
    assert calls[0][0] == ("93.184.216.34", 443)
    assert calls[0][1] == pytest.approx(3.0)
    assert ipaddress.ip_address(calls[0][0][0]).is_global


def test_proxy_revalidates_each_connect_and_rejects_redirect_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tinlance_agent_platform_sandbox.egress_proxy as proxy_module

    upstream, peer = socket.socketpair()
    peer.close()
    monkeypatch.setattr(proxy_module, "_system_resolve", lambda _: ("93.184.216.34",))
    monkeypatch.setattr(
        proxy_module,
        "connect_pinned_target",
        lambda *_args, **_kwargs: upstream,
    )
    proxy = BrowserEgressProxy(
        "127.0.0.1",
        0,
        policy(),
        allowed_client_network="127.0.0.1/32",
    )
    proxy.start()
    try:
        host, port = proxy.address
        with socket.create_connection((host, port), timeout=3) as client:
            client.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            first_response = client.recv(1024)
        assert first_response.startswith(b"HTTP/1.1 200")

        with socket.create_connection((host, port), timeout=3) as redirected:
            redirected.sendall(
                b"CONNECT 169.254.169.254:443 HTTP/1.1\r\n"
                b"Host: 169.254.169.254:443\r\n\r\n"
            )
            redirect_response = redirected.recv(1024)
        assert redirect_response.startswith(b"HTTP/1.1 403")
    finally:
        proxy.close()
        upstream.close()



def test_proxy_cannot_bind_public_or_wildcard_interfaces() -> None:
    with pytest.raises(ValueError, match="specific private"):
        BrowserEgressProxy(
            "0.0.0.0",
            3128,
            policy(),
            allowed_client_network="127.0.0.1/32",
        )
    with pytest.raises(ValueError, match="private workspace"):
        BrowserEgressProxy(
            "10.253.0.1",
            3128,
            policy(),
            allowed_client_network="0.0.0.0/0",
        )


def test_egress_policy_rejects_unbounded_resource_limits() -> None:
    with pytest.raises(ValueError, match="resource limits"):
        EgressPolicy(
            allowed_domains=frozenset({"example.com"}),
            tunnel_max_seconds=float("inf"),
        )
    with pytest.raises(ValueError, match="resource limits"):
        EgressPolicy(
            allowed_domains=frozenset({"example.com"}),
            max_connections=10_000,
        )


def test_same_allowlisted_hostname_is_revalidated_against_dns_rebinding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tinlance_agent_platform_sandbox.egress_proxy as proxy_module

    upstream, peer = socket.socketpair()
    peer.close()
    dns_answers = iter(
        [
            ("93.184.216.34",),
            ("169.254.169.254",),
        ]
    )
    resolver_calls: list[str] = []
    connector_calls: list[ResolvedTarget] = []

    def changing_resolver(hostname: str) -> tuple[str, ...]:
        resolver_calls.append(hostname)
        return next(dns_answers)

    def pinned_connector(target: ResolvedTarget, *, timeout_seconds: float) -> socket.socket:
        connector_calls.append(target)
        return upstream

    monkeypatch.setattr(proxy_module, "_system_resolve", changing_resolver)
    monkeypatch.setattr(proxy_module, "connect_pinned_target", pinned_connector)
    proxy = BrowserEgressProxy(
        "127.0.0.1",
        0,
        policy(),
        allowed_client_network="127.0.0.1/32",
    )
    proxy.start()
    try:
        host, port = proxy.address
        with socket.create_connection((host, port), timeout=3) as first:
            first.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            first_response = first.recv(1024)
        assert first_response.startswith(b"HTTP/1.1 200")

        with socket.create_connection((host, port), timeout=3) as rebound:
            rebound.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            rebound_response = rebound.recv(1024)
        assert rebound_response.startswith(b"HTTP/1.1 403")
        assert resolver_calls == ["example.com", "example.com"]
        assert len(connector_calls) == 1
        assert connector_calls[0].addresses == ("93.184.216.34",)
    finally:
        proxy.close()
        upstream.close()


def test_proxy_close_terminates_active_tunnels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tinlance_agent_platform_sandbox.egress_proxy as proxy_module

    upstream, peer = socket.socketpair()
    monkeypatch.setattr(proxy_module, "_system_resolve", lambda _: ("93.184.216.34",))
    monkeypatch.setattr(
        proxy_module,
        "connect_pinned_target",
        lambda *_args, **_kwargs: upstream,
    )
    proxy = BrowserEgressProxy(
        "127.0.0.1",
        0,
        policy(),
        allowed_client_network="127.0.0.1/32",
    )
    proxy.start()
    client = socket.create_connection(proxy.address, timeout=3)
    try:
        client.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        assert client.recv(1024).startswith(b"HTTP/1.1 200")

        proxy.close()
        client.settimeout(1)
        with contextlib.suppress(ConnectionResetError):
            assert client.recv(1) == b""
        peer.settimeout(1)
        assert peer.recv(1) == b""
    finally:
        client.close()
        proxy.close()
        upstream.close()
        peer.close()


def test_connector_uses_one_deadline_across_all_validated_addresses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tinlance_agent_platform_sandbox.egress_proxy as proxy_module

    class FakeClock:
        current = 0.0

        @classmethod
        def monotonic(cls) -> float:
            return cls.current

    fake_socket = socket.socket()
    calls: list[tuple[tuple[str, int], float]] = []

    def fake_create_connection(
        address: tuple[str, int],
        timeout: float,
    ) -> socket.socket:
        calls.append((address, timeout))
        if len(calls) == 1:
            FakeClock.current = 2.0
            raise TimeoutError("first validated address timed out")
        return fake_socket

    monkeypatch.setattr(proxy_module, "time", FakeClock)
    monkeypatch.setattr(proxy_module.socket, "create_connection", fake_create_connection)
    target = ResolvedTarget(
        "example.com",
        443,
        ("93.184.216.34", "93.184.216.35"),
    )
    try:
        result = connect_pinned_target(target, timeout_seconds=3.0)
        assert result is fake_socket
        assert calls == [
            (("93.184.216.34", 443), 3.0),
            (("93.184.216.35", 443), 1.0),
        ]
    finally:
        fake_socket.close()
