from __future__ import annotations

import os

import pytest
from scripts.browser_egress_network import (
    build_host_forwarding_rules,
    build_proxy_namespace_rules,
    validate_proxy_namespace_routes,
)


def test_proxy_namespace_allows_only_https_and_explicit_dns() -> None:
    rules = build_proxy_namespace_rules(
        browser_interface="tbbr0",
        uplink_interface="tbup0",
        dns_server="1.1.1.1",
    )
    assert "tcp dport 443 accept" in rules
    assert "ip daddr 1.1.1.1 udp dport 53 accept" in rules
    assert "ip daddr 1.1.1.1 tcp dport 53 accept" in rules
    assert "policy drop" in rules
    assert "tcp dport 80 accept" not in rules
    assert "169.254.0.0/16" in rules
    assert "10.0.0.0/8" in rules
    assert "192.88.99.0/24" in rules


def test_generated_harness_veth_names_with_full_random_suffix_are_accepted() -> None:
    rules = build_proxy_namespace_rules(
        browser_interface="tbpbdeadbeef",
        uplink_interface="tbupdeadbeef",
        dns_server="1.1.1.1",
    )
    assert 'iifname "tbpbdeadbeef" tcp dport 3128 accept' in rules
    assert 'oifname "tbupdeadbeef" ip daddr' in rules


def test_host_forwarding_rules_only_nat_proxy_uplink() -> None:
    rules = build_host_forwarding_rules(
        proxy_host_interface="tbup0",
        proxy_subnet="10.255.4.0/30",
        dns_server="1.1.1.1",
        host_dns_ip="10.255.4.1",
    )
    assert 'iifname "tbup0" ip daddr 10.255.4.1 udp dport 53 accept' in rules
    assert 'iifname "tbup0" ip daddr 10.255.4.1 tcp dport 53 accept' in rules
    assert 'iifname "tbup0" ip daddr != {' in rules
    assert "tcp dport 443 accept" in rules
    assert 'iifname "tbup0" ip daddr 1.1.1.1 udp dport 53 accept' in rules
    assert 'iifname "tbup0" drop' in rules
    assert "type filter hook forward priority -50; policy accept;" in rules
    assert 'ip saddr 10.255.4.0/30 oifname != "tbup0" masquerade' in rules


def test_proxy_namespace_route_validation_rejects_unapproved_routes() -> None:
    browser = "10.254.4.0/30 dev tbbr0 proto kernel scope link src 10.254.4.2"
    uplink = "10.255.4.0/30 dev tbup0 proto kernel scope link src 10.255.4.2"
    valid = browser + "\n" + uplink + "\ndefault via 10.255.4.1 dev tbup0"
    assert (
        validate_proxy_namespace_routes(
            valid,
            "10.254.4.0/30",
            "10.255.4.0/30",
            "10.255.4.1",
            "tbbr0",
            "tbup0",
        )
        is True
    )
    with pytest.raises(ValueError, match="approved gateway"):
        validate_proxy_namespace_routes(
            browser + "\n" + uplink + "\ndefault via 10.255.4.254 dev tbup0",
            "10.254.4.0/30",
            "10.255.4.0/30",
            "10.255.4.1",
            "tbbr0",
            "tbup0",
        )
    with pytest.raises(ValueError, match="unexpected route"):
        validate_proxy_namespace_routes(
            browser
            + "\n192.168.1.0/24 dev tbbr0 scope link"
            + "\ndefault via 10.255.4.1 dev tbup0",
            "10.254.4.0/30",
            "10.255.4.0/30",
            "10.255.4.1",
            "tbbr0",
            "tbup0",
        )
    with pytest.raises(ValueError, match="approved uplink"):
        validate_proxy_namespace_routes(
            browser + "\n" + uplink + "\ndefault via 10.255.4.1 dev",
            "10.254.4.0/30",
            "10.255.4.0/30",
            "10.255.4.1",
            "tbbr0",
            "tbup0",
        )
    with pytest.raises(ValueError, match="unexpected route"):
        validate_proxy_namespace_routes(
            browser.replace("dev tbbr0", "dev")
            + "\n"
            + uplink
            + "\ndefault via 10.255.4.1 dev tbup0",
            "10.254.4.0/30",
            "10.255.4.0/30",
            "10.255.4.1",
            "tbbr0",
            "tbup0",
        )


@pytest.mark.parametrize("name", ["", "lo", "eth0", "a;drop"])
def test_interface_names_are_rejected_unless_owned_by_the_harness(name: str) -> None:
    with pytest.raises(ValueError):
        build_proxy_namespace_rules(
            browser_interface=name,
            uplink_interface="tbup0",
            dns_server="1.1.1.1",
        )


@pytest.mark.parametrize("dns_server", ["127.0.0.1", "169.254.169.254", "::1"])
def test_dns_forwarder_rejects_unreachable_or_special_addresses(dns_server: str) -> None:
    with pytest.raises(ValueError, match="DNS forwarder"):
        build_proxy_namespace_rules(
            browser_interface="tbbr0",
            uplink_interface="tbup0",
            dns_server=dns_server,
        )


def test_explicit_private_dns_resolver_is_allowed_by_exact_destination_policy() -> None:
    rules = build_proxy_namespace_rules(
        browser_interface="tbbr0",
        uplink_interface="tbup0",
        dns_server="10.0.0.2",
    )
    assert "ip daddr 10.0.0.2 udp dport 53 accept" in rules
    assert "ip daddr 10.0.0.2 tcp dport 53 accept" in rules


def test_proxy_resolver_config_is_readable_only_by_proxy_identity(tmp_path) -> None:
    from scripts.browser_egress_network import write_proxy_resolver_config

    config = write_proxy_resolver_config(
        tmp_path,
        dns_server="1.1.1.1",
    )
    metadata = config.stat()
    assert metadata.st_uid == os.geteuid()
    assert metadata.st_gid == os.getegid()
    assert metadata.st_mode & 0o777 == 0o600
    assert config.read_text(encoding="ascii") == (
        "nameserver 1.1.1.1"
        + chr(10)
        + "options timeout:2 attempts:1"
        + chr(10)
    )
