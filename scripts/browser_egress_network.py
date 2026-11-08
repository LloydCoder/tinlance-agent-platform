"""W4 network policy primitives for an egress-only browser proxy namespace."""

from __future__ import annotations

import ipaddress
import os
import re
import stat
from pathlib import Path

_NON_PUBLIC_V4_SET = (
    "{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, "
    "127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, "
    "192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, "
    "192.168.0.0/16, "
    "198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, "
    "224.0.0.0/4, 240.0.0.0/4 }"
)

_INTERFACE = re.compile(r"^tb[a-z0-9]{1,10}$")


def _interface(value: str) -> str:
    if not isinstance(value, str) or not _INTERFACE.fullmatch(value):
        raise ValueError("network interface must be a harness-owned tb-prefixed name")
    return value


def _dns_server(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("DNS forwarding requires an explicit IP literal") from exc
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        raise ValueError("DNS forwarder must be an explicitly approved, reachable IPv4 resolver")
    return str(address)


def build_proxy_namespace_rules(
    *, browser_interface: str, uplink_interface: str, dns_server: str
) -> str:
    """Return default-deny namespace firewall rules for proxy ingress and egress."""
    browser = _interface(browser_interface)
    uplink = _interface(uplink_interface)
    if browser == uplink:
        raise ValueError("browser and uplink interfaces must be distinct")
    dns = _dns_server(dns_server)
    return f"""table inet tnl_proxy {{
  chain input {{
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state established,related accept
    iifname "{browser}" tcp dport 3128 accept
  }}
  chain output {{
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ct state established,related accept
    oifname "{uplink}" ip daddr != {_NON_PUBLIC_V4_SET} fib daddr type unicast tcp dport 443 accept
    oifname "{uplink}" ip daddr {dns} udp dport 53 accept
    oifname "{uplink}" ip daddr {dns} tcp dport 53 accept
  }}
}}
"""


def build_host_forwarding_rules(
    *,
    proxy_host_interface: str,
    proxy_subnet: str,
    host_dns_ip: str,
) -> str:
    """Restrict host DNS ingress and proxy forwarding to the dedicated uplink."""
    uplink = _interface(proxy_host_interface)
    dns = ipaddress.ip_address(host_dns_ip)
    subnet = ipaddress.ip_network(proxy_subnet, strict=True)
    if subnet.version != 4 or not subnet.is_private:
        raise ValueError("proxy uplink must use a private IPv4 subnet")
    if dns.version != 4 or dns not in subnet:
        raise ValueError("host DNS relay must bind to the proxy uplink subnet")
    return f"""table inet tnl_w4_forward {{
  chain input {{
    type filter hook input priority -50; policy accept;
    iifname "{uplink}" ip daddr {dns} udp dport 53 accept
    iifname "{uplink}" ip daddr {dns} tcp dport 53 accept
    iifname "{uplink}" drop
  }}
  chain forward {{
    type filter hook forward priority -50; policy accept;
    ct state established,related accept
    iifname "{uplink}" ip daddr != {_NON_PUBLIC_V4_SET} tcp dport 443 accept
    iifname "{uplink}" drop
  }}
}}
table ip tnl_w4_nat {{
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr {subnet} oifname != "{uplink}" masquerade
  }}
}}
"""


def validate_proxy_namespace_routes(
    routes: str,
    browser_network: str,
    uplink_network: str,
    expected_default_gateway: str,
    expected_browser_interface: str,
    expected_uplink_interface: str,
) -> bool:
    """Require two approved connected routes and one approved egress default."""
    browser = ipaddress.ip_network(browser_network, strict=True)
    uplink = ipaddress.ip_network(uplink_network, strict=True)
    gateway = ipaddress.ip_address(expected_default_gateway)
    if (
        browser.version != 4
        or uplink.version != 4
        or not browser.is_private
        or not uplink.is_private
        or browser.overlaps(uplink)
        or gateway.version != 4
        or gateway not in uplink
    ):
        raise ValueError("proxy route policy requires distinct private IPv4 links")
    browser_interface = _interface(expected_browser_interface)
    uplink_interface = _interface(expected_uplink_interface)
    if browser_interface == uplink_interface:
        raise ValueError("proxy route interfaces must be distinct")
    lines = [line.split() for line in routes.splitlines() if line.strip()]
    if len(lines) != 3:
        raise ValueError("proxy namespace contains an unexpected route")
    connected: set[ipaddress.IPv4Network] = set()
    default = False
    for fields in lines:
        if fields[0] == "default":
            if len(fields) < 4 or fields[1] != "via" or fields[2] != str(gateway):
                raise ValueError("proxy namespace default route does not use approved gateway")
            device_index = fields.index("dev") if "dev" in fields else -1
            if (
                device_index < 0
                or device_index + 1 >= len(fields)
                or fields[device_index + 1] != uplink_interface
            ):
                raise ValueError("proxy namespace default route does not use the approved uplink")
            default = True
            continue
        try:
            network = ipaddress.ip_network(fields[0], strict=False)
        except ValueError as exc:
            raise ValueError("proxy namespace contains an unexpected route") from exc
        device_index = fields.index("dev") if "dev" in fields else -1
        if network not in {browser, uplink} or device_index < 0 or device_index + 1 >= len(fields):
            raise ValueError("proxy namespace contains an unexpected route")
        expected_interface = browser_interface if network == browser else uplink_interface
        if fields[device_index + 1] != expected_interface:
            raise ValueError("proxy namespace contains an unexpected route interface")
        connected.add(network)
    if connected != {browser, uplink} or not default:
        raise ValueError("proxy namespace routes do not match the approved topology")
    return True


def write_proxy_resolver_config(
    directory: str | os.PathLike[str],
    *,
    dns_server: str,
    proxy_uid: int | None = None,
    proxy_gid: int | None = None,
) -> Path:
    """Create a resolver file readable only by the proxy workload identity."""
    if (proxy_uid is None) != (proxy_gid is None):
        raise ValueError("proxy resolver ownership requires both UID and GID")
    target = Path(directory) / "resolv.conf"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        if proxy_uid is not None and proxy_gid is not None:
            os.fchown(descriptor, proxy_uid, proxy_gid)
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            descriptor = -1
            stream.write(
                "nameserver "
                + _dns_server(dns_server)
                + chr(10)
                + "options timeout:2 attempts:1"
                + chr(10)
            )
        metadata = target.stat(follow_symlinks=False)
        expected_uid = os.geteuid() if proxy_uid is None else proxy_uid
        expected_gid = os.getegid() if proxy_gid is None else proxy_gid
        if (
            stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
        ):
            raise PermissionError("proxy resolver config ownership or mode is not private")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return target
