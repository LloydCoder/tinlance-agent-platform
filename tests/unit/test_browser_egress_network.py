from __future__ import annotations

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


def test_host_forwarding_rules_only_nat_proxy_uplink() -> None:
    rules = build_host_forwarding_rules(
        proxy_host_interface="tbup0",
        proxy_subnet="10.255.4.0/30",
    )
    assert 'iifname "tbup0" tcp dport 443 accept' in rules
    assert 'iifname "tbup0" ip daddr 1.1.1.1 udp dport 53 accept' in rules
    assert 'iifname "tbup0" drop' in rules
    assert "type filter hook forward priority -50; policy accept;" in rules
    assert 'ip saddr 10.255.4.0/30 masquerade' in rules


def test_proxy_namespace_route_validation_rejects_unapproved_routes() -> None:
    browser = "10.254.4.0/30 dev tbbr0 proto kernel scope link src 10.254.4.2"
    uplink = "10.255.4.0/30 dev tbup0 proto kernel scope link src 10.255.4.2"
    valid = browser + "\n" + uplink + "\ndefault via 10.255.4.1 dev tbup0"
    assert validate_proxy_namespace_routes(
        valid, "10.254.4.0/30", "10.255.4.0/30", "10.255.4.1"
    ) is True
    with pytest.raises(ValueError, match="approved gateway"):
        validate_proxy_namespace_routes(
            browser + "\n" + uplink + "\ndefault via 10.255.4.254 dev tbup0",
            "10.254.4.0/30",
            "10.255.4.0/30",
            "10.255.4.1",
        )
    with pytest.raises(ValueError, match="unexpected route"):
        validate_proxy_namespace_routes(
            browser + "\n192.168.1.0/24 dev tbbr0 scope link"
            + "\ndefault via 10.255.4.1 dev tbup0",
            "10.254.4.0/30",
            "10.255.4.0/30",
            "10.255.4.1",
        )


@pytest.mark.parametrize("name", ["", "lo", "eth0", "a;drop"])
def test_interface_names_are_rejected_unless_owned_by_the_harness(name: str) -> None:
    with pytest.raises(ValueError):
        build_proxy_namespace_rules(
            browser_interface=name,
            uplink_interface="tbup0",
            dns_server="1.1.1.1",
        )
