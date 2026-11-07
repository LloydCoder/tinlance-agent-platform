from __future__ import annotations

import ipaddress
import socket

import pytest

from tinlance_agent_platform_sandbox.egress_proxy import (
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
    assert resolve_public_target(
        "docs.example.com", 443, wildcard, resolver=lambda _: ("93.184.216.34",)
    ).hostname == "docs.example.com"
    with pytest.raises(EgressDenied):
        resolve_public_target(
            "example.com", 443, wildcard, resolver=lambda _: ("93.184.216.34",)
        )


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
        resolve_public_target(
            hostname, 443, policy(), resolver=lambda _: ("93.184.216.34",)
        )


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
        resolve_public_target(
            "example.com", 443, policy(), resolver=lambda _: (address,)
        )


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
        resolve_public_target(
            "example.com", 80, policy(), resolver=lambda _: ("93.184.216.34",)
        )


def test_invalid_idna_hostname_is_rejected() -> None:
    with pytest.raises(EgressDenied):
        normalize_hostname("bad..example.com")


def test_connector_uses_validated_ip_literal_without_hostname_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
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
    assert calls == [(("93.184.216.34", 443), 3.0)]
    assert ipaddress.ip_address(calls[0][0][0]).is_global
