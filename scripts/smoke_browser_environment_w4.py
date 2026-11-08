from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import secrets
import select
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from browser_egress_network import (
    build_host_forwarding_rules,
    build_proxy_namespace_rules,
    build_host_iptables_forward_rules,
    validate_proxy_namespace_routes,
    write_proxy_resolver_config,
)

PROXY_PORT = 3128


def select_approved_dns_server() -> tuple[str, str]:
    for resolver_file in (
        Path("/etc/resolv.conf"),
        Path("/run/systemd/resolve/resolv.conf"),
        Path("/run/NetworkManager/no-stub-resolv.conf"),
    ):
        if not resolver_file.is_file():
            continue
        for line in resolver_file.read_text(encoding="ascii", errors="replace").splitlines():
            fields = line.split()
            if len(fields) < 2 or fields[0] != "nameserver":
                continue
            try:
                address = ipaddress.ip_address(fields[1])
            except ValueError:
                continue
            if (
                isinstance(address, ipaddress.IPv4Address)
                and not address.is_multicast
                and not address.is_unspecified
                and not address.is_reserved
            ):
                return str(address), str(resolver_file)
    return "1.1.1.1", "explicit Cloudflare fallback"


DNS_SERVER, DNS_SERVER_SOURCE = select_approved_dns_server()


def run(command: list[str], *, timeout: int = 30, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        command, check=True, capture_output=True, text=True, timeout=timeout, env=env
    )
    return result.stdout.strip()


class _DNSRelayServer:
    def __init__(self, bind_ip: str, upstream_ip: str) -> None:
        self.udp = _DNSUDPServer((bind_ip, 53), upstream_ip)
        self.tcp = _DNSTCPServer((bind_ip, 53), upstream_ip)
        self.threads = [
            threading.Thread(target=self.udp.serve_forever, daemon=True),
            threading.Thread(target=self.tcp.serve_forever, daemon=True),
        ]
        for thread in self.threads:
            thread.start()

    def close(self) -> None:
        for server in (self.udp, self.tcp):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)


class _DNSUDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        payload, client_socket = self.request
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
                upstream.settimeout(3)
                upstream.sendto(payload, (self.server.upstream_ip, 53))
                response, _ = upstream.recvfrom(65535)
            client_socket.sendto(response, self.client_address)
        except OSError:
            return


class _DNSTCPHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(5)
        while True:
            header = self.rfile.read(2)
            if len(header) != 2:
                return
            size = int.from_bytes(header, "big")
            if not 12 <= size <= 65535:
                return
            query = self.rfile.read(size)
            if len(query) != size:
                return
            try:
                with socket.create_connection((self.server.upstream_ip, 53), timeout=3) as upstream:
                    upstream.sendall(header + query)
                    response_header = _read_dns_bytes(upstream, 2)
                    response_size = int.from_bytes(response_header, "big")
                    response = _read_dns_bytes(upstream, response_size)
                self.wfile.write(response_header + response)
            except OSError:
                return


def _read_dns_bytes(connection: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise ConnectionError("DNS upstream closed a truncated response")
        result.extend(chunk)
    return bytes(result)


class _DNSUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], upstream_ip: str) -> None:
        self.upstream_ip = upstream_ip
        super().__init__(address, _DNSUDPHandler)


class _DNSTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], upstream_ip: str) -> None:
        self.upstream_ip = upstream_ip
        super().__init__(address, _DNSTCPHandler)


def child_environment(home: Path, tmpdir: Path, *, playwright: bool = False) -> dict[str, str]:
    allowed = {"PATH", "PYTHONPATH", "LD_LIBRARY_PATH", "LANG", "LC_ALL"}
    if playwright:
        allowed.add("PLAYWRIGHT_BROWSERS_PATH")
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment.update({"HOME": str(home), "TMPDIR": str(tmpdir)})
    if playwright:
        environment["XDG_CONFIG_HOME"] = str(home / ".config")
        environment["XDG_CACHE_HOME"] = str(home / ".cache")
    return environment


def create_user(name: str, start_uid: int) -> tuple[int, int]:
    for uid in range(start_uid, start_uid + 1000):
        if subprocess.run(["getent", "passwd", str(uid)], capture_output=True).returncode == 0:
            continue
        if subprocess.run(["getent", "group", str(uid)], capture_output=True).returncode == 0:
            continue
        run(
            [
                "useradd",
                "--uid",
                str(uid),
                "--user-group",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                name,
            ]
        )
        return uid, int(run(["id", "-g", name]))
    raise RuntimeError("no free UID/GID available for W4 isolation identities")


def probe_blocked(namespace: str, destination: str, port: int) -> bool:
    script = (
        "import socket\n"
        f"target = ({destination!r}, {port})\n"
        "try:\n"
        "    socket.create_connection(target, timeout=1)\n"
        "    print('REACHED')\n"
        "except OSError:\n"
        "    print('BLOCKED')\n"
    )
    output = run(["ip", "netns", "exec", namespace, sys.executable, "-c", script], timeout=4)
    if output != "BLOCKED":
        raise RuntimeError(
            f"proxy namespace unexpectedly reached restricted destination {destination}:{port}"
        )
    return True


def main() -> int:
    if os.name != "posix" or os.geteuid() != 0:
        raise SystemExit("W4 namespace acceptance must run as root")

    suffix = secrets.token_hex(4)
    browser_ns = f"tnlbr-{suffix}"
    proxy_ns = f"tnlpx-{suffix}"
    browser_if = f"tbbr{suffix}"
    proxy_browser_if = f"tbpb{suffix}"
    host_uplink_if = f"tbuh{suffix}"
    proxy_uplink_if = f"tbup{suffix}"
    host_forward_table = f"tnlw4f_{suffix}"
    host_nat_table = f"tnlw4n_{suffix}"

    octet = secrets.randbelow(256)
    base = secrets.randbelow(64) * 4
    browser_network = ipaddress.IPv4Network(f"10.254.{octet}.{base}/30")
    uplink_network = ipaddress.IPv4Network(f"10.255.{octet}.{base}/30")
    browser_ip = str(browser_network.network_address + 2)
    proxy_browser_ip = str(browser_network.network_address + 1)
    host_uplink_ip = str(uplink_network.network_address + 1)
    proxy_uplink_ip = str(uplink_network.network_address + 2)
    host_probe_port = 49152 + secrets.randbelow(16384)

    browser_name = f"tnlbr-a-{suffix}"
    proxy_name = f"tnlbr-p-{suffix}"
    other_name = f"tnlbr-b-{suffix}"
    tenant_b_ns = f"tnltb-{suffix}"
    users: list[str] = []
    namespaces: list[str] = []
    host_link_created = False
    host_link_deleted = False
    host_rules_created = False
    proxy_process: subprocess.Popen[bytes] | None = None
    tenant_a_probe: subprocess.Popen[str] | None = None
    listener: socket.socket | None = None
    listener_thread: threading.Thread | None = None
    dns_relay: _DNSRelayServer | None = None
    host_iptables_chain: str | None = None
    host_iptables_rules: list[tuple[str, ...]] = []
    resolv_dir = Path("/etc/netns") / proxy_ns
    old_forward = Path("/proc/sys/net/ipv4/ip_forward").read_text(encoding="ascii").strip()
    work = Path(tempfile.mkdtemp(prefix="tinlance-browser-w4-"))
    artifacts = Path("artifacts")
    evidence: dict[str, object] = {
        "schema_version": 1,
        "phase": "W4",
        "status": "running",
        "production_certification": False,
        "browser_network_namespace": browser_ns,
        "proxy_network_namespace": proxy_ns,
        "browser_namespace_has_no_default_route": False,
        "proxy_namespace_has_approved_default_route": False,
        "proxy_namespace_firewall_restrictive": False,
        "proxy_namespace_host_services_blocked": False,
        "proxy_namespace_private_egress_blocked": False,
        "proxy_namespace_unapproved_port_blocked": False,
        "browser_direct_egress_blocked": False,
        "cross_tenant_profile_reuse_denied": False,
        "concurrent_cross_tenant_isolation": False,
        "namespace_escape_probes_passed": False,
        "cleanup_verified": False,
    }

    try:
        browser_uid, browser_gid = create_user(browser_name, 51_000)
        users.append(browser_name)
        proxy_uid, proxy_gid = create_user(proxy_name, 52_000)
        users.append(proxy_name)
        other_uid, other_gid = create_user(other_name, 53_000)
        users.append(other_name)

        profile_root = work / "profile"
        home = work / "home"
        tmpdir = work / "tmp"
        guest_evidence_path = work / "guest-evidence.json"
        os.chown(work, browser_uid, browser_gid)
        os.chmod(work, 0o700)
        for path in (profile_root, home, tmpdir):
            path.mkdir(mode=0o700)
            os.chown(path, browser_uid, browser_gid)
            os.chmod(path, 0o700)

        run(["ip", "netns", "add", browser_ns])
        namespaces.append(browser_ns)
        run(["ip", "netns", "add", proxy_ns])
        namespaces.append(proxy_ns)
        run(["ip", "netns", "add", tenant_b_ns])
        namespaces.append(tenant_b_ns)

        # Browser-to-proxy traffic uses a direct veth pair; neither endpoint
        # exists in the host namespace.
        run(["ip", "link", "add", browser_if, "type", "veth", "peer", "name", proxy_browser_if])
        run(["ip", "link", "set", browser_if, "netns", browser_ns])
        run(["ip", "link", "set", proxy_browser_if, "netns", proxy_ns])
        run(
            [
                "ip",
                "netns",
                "exec",
                browser_ns,
                "ip",
                "addr",
                "add",
                f"{browser_ip}/30",
                "dev",
                browser_if,
            ]
        )
        run(
            [
                "ip",
                "netns",
                "exec",
                proxy_ns,
                "ip",
                "addr",
                "add",
                f"{proxy_browser_ip}/30",
                "dev",
                proxy_browser_if,
            ]
        )
        run(["ip", "netns", "exec", browser_ns, "ip", "link", "set", browser_if, "up"])
        run(["ip", "netns", "exec", proxy_ns, "ip", "link", "set", proxy_browser_if, "up"])

        # A second, independent veth is the proxy's only host-facing uplink.
        run(["ip", "link", "add", host_uplink_if, "type", "veth", "peer", "name", proxy_uplink_if])
        host_link_created = True
        run(["ip", "link", "set", proxy_uplink_if, "netns", proxy_ns])
        run(["ip", "addr", "add", f"{host_uplink_ip}/30", "dev", host_uplink_if])
        run(["ip", "link", "set", host_uplink_if, "up"])
        run(
            [
                "ip",
                "netns",
                "exec",
                proxy_ns,
                "ip",
                "addr",
                "add",
                f"{proxy_uplink_ip}/30",
                "dev",
                proxy_uplink_if,
            ]
        )
        run(["ip", "netns", "exec", proxy_ns, "ip", "link", "set", proxy_uplink_if, "up"])
        run(
            [
                "ip",
                "netns",
                "exec",
                proxy_ns,
                "ip",
                "route",
                "add",
                "default",
                "via",
                host_uplink_ip,
                "dev",
                proxy_uplink_if,
            ]
        )

        for netns, interfaces in (
            (browser_ns, (browser_if,)),
            (proxy_ns, (proxy_browser_if, proxy_uplink_if)),
            (tenant_b_ns, ()),
        ):
            run(["ip", "netns", "exec", netns, "ip", "link", "set", "lo", "up"])
            run(["ip", "netns", "exec", netns, "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"])
            run(
                [
                    "ip",
                    "netns",
                    "exec",
                    netns,
                    "sysctl",
                    "-w",
                    "net.ipv6.conf.default.disable_ipv6=1",
                ]
            )
            run(["ip", "netns", "exec", netns, "sysctl", "-w", "net.ipv6.conf.all.accept_ra=0"])
            run(["ip", "netns", "exec", netns, "sysctl", "-w", "net.ipv6.conf.default.accept_ra=0"])
            run(["ip", "netns", "exec", netns, "sysctl", "-w", "net.ipv6.conf.lo.disable_ipv6=1"])
            for interface in interfaces:
                run(
                    [
                        "ip",
                        "netns",
                        "exec",
                        netns,
                        "sysctl",
                        "-w",
                        f"net.ipv6.conf.{interface}.disable_ipv6=1",
                    ]
                )
                run(
                    [
                        "ip",
                        "netns",
                        "exec",
                        netns,
                        "sysctl",
                        "-w",
                        f"net.ipv6.conf.{interface}.accept_ra=0",
                    ]
                )
            run(
                [
                    "ip",
                    "netns",
                    "exec",
                    netns,
                    "ip",
                    "-6",
                    "route",
                    "flush",
                    "table",
                    "all",
                    "default",
                ]
            )
        run(["ip", "netns", "exec", proxy_ns, "sysctl", "-w", "net.ipv4.ip_forward=0"])
        for netns in (browser_ns, proxy_ns, tenant_b_ns):
            ipv6_disabled = run(
                [
                    "ip",
                    "netns",
                    "exec",
                    netns,
                    "sysctl",
                    "-n",
                    "net.ipv6.conf.all.disable_ipv6",
                ]
            )
            ipv6_routes = run(["ip", "netns", "exec", netns, "ip", "-6", "route", "show"])
            if ipv6_disabled != "1" or ipv6_routes:
                raise RuntimeError(f"IPv6 is not fully disabled in namespace {netns}")

        dns_relay = _DNSRelayServer(host_uplink_ip, DNS_SERVER)
        evidence["host_dns_upstream"] = DNS_SERVER
        evidence["host_dns_upstream_source"] = DNS_SERVER_SOURCE
        resolv_dir.mkdir(parents=True, exist_ok=False)
        resolver_config = write_proxy_resolver_config(
            resolv_dir,
            dns_server=host_uplink_ip,
            proxy_uid=proxy_uid,
            proxy_gid=proxy_gid,
        )
        resolver_metadata = resolver_config.stat(follow_symlinks=False)
        evidence["proxy_resolver_config_private"] = (
            resolver_metadata.st_uid == proxy_uid
            and resolver_metadata.st_gid == proxy_gid
            and (resolver_metadata.st_mode & 0o777) == 0o600
        )
        if evidence["proxy_resolver_config_private"] is not True:
            raise RuntimeError("proxy resolver configuration is not private to its workload identity")

        proxy_rules = build_proxy_namespace_rules(
            browser_interface=proxy_browser_if,
            uplink_interface=proxy_uplink_if,
            dns_server=host_uplink_ip,
        )
        subprocess.run(
            ["ip", "netns", "exec", proxy_ns, "nft", "-f", "-"],
            input=proxy_rules,
            check=True,
            capture_output=True,
            text=True,
        )
        host_rules = (
            build_host_forwarding_rules(
                proxy_host_interface=host_uplink_if,
                proxy_subnet=str(uplink_network),
                host_dns_ip=host_uplink_ip,
            )
            .replace("tnl_w4_forward", host_forward_table)
            .replace("tnl_w4_nat", host_nat_table)
        )
        run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        subprocess.run(
            ["nft", "-f", "-"],
            input=host_rules,
            check=True,
            capture_output=True,
            text=True,
        )
        host_rules_created = True

        host_route = run(["ip", "-4", "route", "get", "1.1.1.1"])
        host_route_fields = host_route.split()
        if "dev" not in host_route_fields:
            raise RuntimeError("host route lookup did not identify an egress interface")
        host_egress_interface = host_route_fields[host_route_fields.index("dev") + 1]
        docker_user = subprocess.run(
            ["iptables", "-S", "DOCKER-USER"], check=False, capture_output=True, text=True
        )
        host_iptables_chain = "DOCKER-USER" if docker_user.returncode == 0 else "FORWARD"
        scoped_rules = build_host_iptables_forward_rules(
            proxy_host_interface=host_uplink_if,
            egress_interface=host_egress_interface,
            proxy_ip=proxy_uplink_ip,
        )
        for rule in scoped_rules:
            subprocess.run(
                ["iptables", "-I", host_iptables_chain, "1", *rule],
                check=True,
                capture_output=True,
                text=True,
            )
            host_iptables_rules.append(rule)
        evidence["host_egress_interface"] = host_egress_interface
        evidence["host_forwarding_chain"] = host_iptables_chain
        evidence["host_scoped_forward_rules_installed"] = True

        browser_routes = run(["ip", "netns", "exec", browser_ns, "ip", "-4", "route", "show"])
        if any(line.split()[:1] == ["default"] for line in browser_routes.splitlines()):
            raise RuntimeError("browser namespace unexpectedly has a default route")
        proxy_routes = run(["ip", "netns", "exec", proxy_ns, "ip", "-4", "route", "show"])
        validate_proxy_namespace_routes(
            proxy_routes,
            str(browser_network),
            str(uplink_network),
            host_uplink_ip,
            proxy_browser_if,
            proxy_uplink_if,
        )
        browser_interfaces = run(["ip", "netns", "exec", browser_ns, "ip", "-o", "link", "show"])
        proxy_interfaces = run(["ip", "netns", "exec", proxy_ns, "ip", "-o", "link", "show"])
        if len(browser_interfaces.splitlines()) != 2 or len(proxy_interfaces.splitlines()) != 3:
            raise RuntimeError("browser or proxy namespace contains an unexpected interface")
        tenant_b_interfaces = run(["ip", "netns", "exec", tenant_b_ns, "ip", "-o", "link", "show"])
        tenant_b_routes = run(["ip", "netns", "exec", tenant_b_ns, "ip", "-4", "route", "show"])
        if len(tenant_b_interfaces.splitlines()) != 1 or tenant_b_routes:
            raise RuntimeError("tenant B must have only loopback and no network routes")
        host_namespace_ids = {
            name: os.stat(f"/proc/self/ns/{name}").st_ino for name in ("pid", "ipc", "mnt")
        }
        host_all_namespace_ids = {
            name: os.stat(f"/proc/self/ns/{name}").st_ino for name in ("pid", "ipc", "mnt", "net")
        }
        namespace_probe = (
            "import json,os; print(json.dumps({name:os.stat('/proc/self/ns/'+name).st_ino "
            "for name in ('pid','ipc','mnt')}))"
        )
        isolated_namespace_ids = json.loads(
            run(
                [
                    "ip",
                    "netns",
                    "exec",
                    browser_ns,
                    "unshare",
                    "--mount",
                    "--pid",
                    "--ipc",
                    "--fork",
                    "--mount-proc",
                    "--propagation",
                    "private",
                    sys.executable,
                    "-c",
                    namespace_probe,
                ]
            )
        )
        if any(
            isolated_namespace_ids[name] == host_namespace_ids[name] for name in host_namespace_ids
        ):
            raise RuntimeError(
                "browser workload did not receive distinct PID, IPC and mount namespaces"
            )
        evidence.update(
            {
                "browser_pid_namespace_isolated": True,
                "browser_ipc_namespace_isolated": True,
                "browser_mount_namespace_isolated": True,
                "browser_namespace_ids": isolated_namespace_ids,
                "host_namespace_ids": host_all_namespace_ids,
            }
        )
        route_probe = subprocess.run(
            ["ip", "-4", "route", "get", "1.1.1.1"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        evidence["host_egress_route"] = route_probe.stdout.strip()[:1000]
        for label, command in (
            ("host_forward_chain", ["iptables", "-S", "FORWARD"]),
            ("host_input_chain", ["iptables", "-S", "INPUT"]),
            ("host_nat_chain", ["iptables", "-t", "nat", "-S", "POSTROUTING"]),
            ("host_nft_ruleset", ["nft", "list", "ruleset"]),
        ):
            diagnostic = subprocess.run(
                command, check=False, capture_output=True, text=True, timeout=5
            )
            evidence[label] = (diagnostic.stdout or diagnostic.stderr)[-12000:]
        host_https_probe = subprocess.run(
            [
                sys.executable,
                "-c",
                "import socket; s=socket.create_connection(('example.com', 443), timeout=5); s.close(); print('HOST_HTTPS_OK')",
            ],
            capture_output=True,
            text=True,
            timeout=8,
            env=child_environment(Path("/tmp"), Path("/tmp")),
        )
        evidence["host_public_https_probe"] = (
            host_https_probe.returncode == 0
            and host_https_probe.stdout.strip() == "HOST_HTTPS_OK"
        )
        if not evidence["host_public_https_probe"]:
            evidence["host_public_https_probe_error"] = (
                host_https_probe.stderr[-1000:] or host_https_probe.stdout[-1000:]
            )

        proxy_network_probe = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                proxy_ns,
                "setpriv",
                "--reuid",
                str(proxy_uid),
                "--regid",
                str(proxy_gid),
                "--clear-groups",
                "--no-new-privs",
                sys.executable,
                "-c",
                (
                    "import socket; "
                    "connection = socket.create_connection(('example.com', 443), timeout=5); "
                    "connection.close(); print('PUBLIC_HTTPS_OK')"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=10,
            env=child_environment(Path("/tmp"), Path("/tmp")),
        )
        evidence["proxy_namespace_public_https_probe"] = (
            proxy_network_probe.returncode == 0
            and proxy_network_probe.stdout.strip() == "PUBLIC_HTTPS_OK"
        )
        if not evidence["proxy_namespace_public_https_probe"]:
            evidence["proxy_network_probe_error"] = (
                proxy_network_probe.stderr[-1500:] or proxy_network_probe.stdout[-1500:]
            )
            raise RuntimeError(
                "proxy namespace cannot resolve and reach the approved public HTTPS probe: "
                f"{evidence['proxy_network_probe_error']}"
            )

        evidence.update(
            {
                "browser_namespace_has_no_default_route": True,
                "browser_ipv6_disabled": True,
                "proxy_ipv6_disabled": True,
                "tenant_b_ipv6_disabled": True,
                "proxy_namespace_has_approved_default_route": True,
                "proxy_namespace_firewall_restrictive": True,
                "browser_namespace_route_table": browser_routes,
                "proxy_namespace_route_table": proxy_routes,
                "browser_namespace_interface_count": 2,
                "proxy_namespace_interface_count": 3,
                "tenant_b_namespace_interface_count": 1,
                "tenant_b_namespace_route_table": tenant_b_routes,
                "proxy_namespace_dns_server": host_uplink_ip,
                "proxy_namespace_egress_policy": "public TCP/443 and DNS to the dedicated host relay only",
                "host_forwarding_policy": (
                    "proxy uplink only; established replies; TCP/443; host DNS relay on UDP/TCP 53"
                ),
            }
        )

        proxy_log = work / "proxy.log"
        proxy_env = child_environment(Path("/tmp"), Path("/tmp"))
        with proxy_log.open("wb") as log_file:
            proxy_process = subprocess.Popen(
                [
                    "ip",
                    "netns",
                    "exec",
                    proxy_ns,
                    "unshare",
                    "--mount",
                    "--pid",
                    "--ipc",
                    "--fork",
                    "--kill-child",
                    "--mount-proc",
                    "--propagation",
                    "private",
                    "setpriv",
                    "--reuid",
                    str(proxy_uid),
                    "--regid",
                    str(proxy_gid),
                    "--clear-groups",
                    "--no-new-privs",
                    sys.executable,
                    "scripts/browser_egress_proxy.py",
                    "--bind-host",
                    proxy_browser_ip,
                    "--port",
                    str(PROXY_PORT),
                    "--client-network",
                    f"{browser_ip}/32",
                    "--allowed-domain",
                    "example.com",
                ],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                cwd=Path(__file__).resolve().parents[1],
                env=proxy_env,
                start_new_session=True,
            )

        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if proxy_process.poll() is not None:
                raise RuntimeError("W4 egress proxy exited before readiness")
            ready = subprocess.run(
                [
                    "ip",
                    "netns",
                    "exec",
                    browser_ns,
                    sys.executable,
                    "-c",
                    f"import socket; s=socket.create_connection(({proxy_browser_ip!r}, "
                    f"{PROXY_PORT}), timeout=1); s.close()",
                ],
                capture_output=True,
                timeout=2,
            )
            if ready.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise TimeoutError("W4 egress proxy did not become reachable from browser namespace")
        evidence["proxy_process_uid"] = proxy_uid
        evidence["proxy_listener_ready"] = True

        # Keep tenant A alive with a private IPC segment while tenant B runs.
        # This makes process, IPC, mount and network separation a concurrent test.
        ipc_key = secrets.randbelow(0x7FFFFFFE) + 1
        tenant_a_code = subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                browser_ns,
                "unshare",
                "--mount",
                "--pid",
                "--ipc",
                "--fork",
                "--kill-child",
                "--mount-proc",
                "--propagation",
                "private",
                "setpriv",
                "--reuid",
                str(browser_uid),
                "--regid",
                str(browser_gid),
                "--clear-groups",
                "--no-new-privs",
                sys.executable,
                "scripts/browser_w4_tenant_a.py",
                "--ipc-key",
                str(ipc_key),
                "--hold-seconds",
                "120",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=Path(__file__).resolve().parents[1],
            env=child_environment(Path("/tmp"), Path("/tmp")),
            start_new_session=True,
        )
        tenant_a_probe = tenant_a_code
        if tenant_a_probe.stdout is None:
            raise RuntimeError("tenant A isolation probe did not expose evidence output")
        ready, _, _ = select.select([tenant_a_probe.stdout], [], [], 10)
        if not ready:
            raise TimeoutError("tenant A did not create its IPC and namespace markers")
        tenant_a_line = tenant_a_probe.stdout.readline()
        if not tenant_a_line:
            error_output = tenant_a_probe.stderr.read() if tenant_a_probe.stderr else ""
            raise RuntimeError(f"tenant A isolation probe exited early: {error_output[-1000:]}")
        tenant_a_record = json.loads(tenant_a_line)
        if tenant_a_record.get("status") != "ready":
            raise RuntimeError("tenant A namespace marker did not initialize")
        if any(
            tenant_a_record["namespace_ids"][name] == host_all_namespace_ids[name]
            for name in host_all_namespace_ids
        ):
            raise RuntimeError("tenant A shares a PID, IPC, mount or network namespace with host")

        # A hostile proxy process cannot reach host-local listeners, metadata,
        # private/link-local destinations or arbitrary non-HTTPS ports.
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host_uplink_ip, host_probe_port))
        listener.listen(1)
        listener.settimeout(0.2)

        def accept_once() -> None:
            try:
                connection, _ = listener.accept()
                connection.close()
            except OSError:
                return

        listener_thread = threading.Thread(target=accept_once, daemon=True)
        listener_thread.start()

        # Temporarily permit the test destination through the proxy namespace
        # firewall so the independent host INPUT drop is what blocks this probe.
        run(
            [
                "ip",
                "netns",
                "exec",
                proxy_ns,
                "nft",
                "insert",
                "rule",
                "inet",
                "tnl_proxy",
                "output",
                "oifname",
                proxy_uplink_if,
                "ip",
                "daddr",
                host_uplink_ip,
                "tcp",
                "dport",
                str(host_probe_port),
                "accept",
            ]
        )
        output_rules = run(
            [
                "ip",
                "netns",
                "exec",
                proxy_ns,
                "nft",
                "-a",
                "list",
                "chain",
                "inet",
                "tnl_proxy",
                "output",
            ]
        )
        probe_handle = next(
            int(line.rsplit("# handle ", 1)[1])
            for line in output_rules.splitlines()
            if host_uplink_ip in line and str(host_probe_port) in line and "# handle " in line
        )
        try:
            host_probe_code = (
                "import socket; s=socket.socket(); s.settimeout(1); "
                f"r=s.connect_ex(({host_uplink_ip!r}, {host_probe_port})); "
                "print('REACHED' if r == 0 else 'BLOCKED')"
            )
            host_probe = subprocess.run(
                [
                    "ip",
                    "netns",
                    "exec",
                    proxy_ns,
                    "setpriv",
                    "--reuid",
                    str(proxy_uid),
                    "--regid",
                    str(proxy_gid),
                    "--clear-groups",
                    "--no-new-privs",
                    sys.executable,
                    "-c",
                    host_probe_code,
                ],
                capture_output=True,
                text=True,
                timeout=4,
            )
            if host_probe.returncode != 0 or host_probe.stdout.strip() != "BLOCKED":
                raise RuntimeError("host INPUT firewall did not block a proxy-to-host connection")
            evidence["proxy_namespace_host_services_blocked"] = True
            evidence["host_local_blocked_by_host_firewall"] = True
        finally:
            run(
                [
                    "ip",
                    "netns",
                    "exec",
                    proxy_ns,
                    "nft",
                    "delete",
                    "rule",
                    "inet",
                    "tnl_proxy",
                    "output",
                    "handle",
                    str(probe_handle),
                ]
            )
        evidence["proxy_namespace_private_egress_blocked"] = probe_blocked(
            proxy_ns, "10.0.0.1", 443
        )
        evidence["proxy_namespace_metadata_egress_blocked"] = probe_blocked(
            proxy_ns, "169.254.169.254", 443
        )
        evidence["proxy_namespace_unapproved_port_blocked"] = probe_blocked(proxy_ns, "1.1.1.1", 80)
        if dns_relay is not None:
            dns_relay.close()
        if listener is not None:
            listener.close()
            listener = None
        if listener_thread is not None:
            listener_thread.join(timeout=1)

        # The browser has no default route and cannot use the proxy uplink
        # directly, even if its proxy configuration is removed or bypassed.
        direct_probe = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                browser_ns,
                "setpriv",
                "--reuid",
                str(browser_uid),
                "--regid",
                str(browser_gid),
                "--clear-groups",
                "--no-new-privs",
                sys.executable,
                "-c",
                "import socket; s=socket.socket(); s.settimeout(1); "
                "r=s.connect_ex(('1.1.1.1', 443)); "
                "print('REACHED' if r == 0 else 'BLOCKED')",
            ],
            capture_output=True,
            text=True,
            timeout=4,
        )
        if direct_probe.returncode != 0 or direct_probe.stdout.strip() != "BLOCKED":
            raise RuntimeError("browser namespace unexpectedly has direct public egress")
        evidence["browser_direct_egress_blocked"] = True

        guest_command = [
            "ip",
            "netns",
            "exec",
            browser_ns,
            "unshare",
            "--mount",
            "--pid",
            "--ipc",
            "--fork",
            "--kill-child",
            "--mount-proc",
            "--propagation",
            "private",
            "setpriv",
            "--reuid",
            str(browser_uid),
            "--regid",
            str(browser_gid),
            "--clear-groups",
            "--no-new-privs",
            sys.executable,
            "scripts/browser_workspace_guest.py",
            "--profile-root",
            str(profile_root),
            "--proxy-url",
            f"http://{proxy_browser_ip}:{PROXY_PORT}",
            "--tenant-id",
            "phase2-w4-tenant-a",
            "--workspace-id",
            "workspace-a",
            "--evidence",
            str(guest_evidence_path),
        ]
        run(guest_command, timeout=180, env=child_environment(home, tmpdir, playwright=True))
        guest_evidence = json.loads(guest_evidence_path.read_text(encoding="utf-8"))
        if guest_evidence.get("status") != "passed":
            raise RuntimeError("W4 Chromium guest acceptance did not pass")
        evidence["guest"] = guest_evidence
        evidence["browser_process_uid"] = browser_uid
        evidence["other_tenant_uid"] = other_uid

        tenant_b_probe = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                tenant_b_ns,
                "unshare",
                "--mount",
                "--pid",
                "--ipc",
                "--fork",
                "--kill-child",
                "--mount-proc",
                "--propagation",
                "private",
                "setpriv",
                "--reuid",
                str(other_uid),
                "--regid",
                str(other_gid),
                "--clear-groups",
                "--no-new-privs",
                sys.executable,
                "scripts/browser_w4_tenant_probe.py",
                "--ipc-key",
                str(ipc_key),
                "--hidden-host-pid",
                str(tenant_a_probe.pid),
                "--proxy-host",
                proxy_browser_ip,
                "--proxy-port",
                str(PROXY_PORT),
                "--profile-root",
                str(profile_root),
                "--tenant-a-namespaces",
                json.dumps(tenant_a_record["namespace_ids"], separators=(",", ":")),
                "--host-namespaces",
                json.dumps(host_all_namespace_ids, separators=(",", ":")),
            ],
            capture_output=True,
            text=True,
            timeout=20,
            env=child_environment(Path("/tmp"), Path("/tmp")),
        )
        if tenant_b_probe.returncode != 0:
            raise RuntimeError(
                f"concurrent cross-tenant isolation probe failed: {tenant_b_probe.stderr[-1500:]}"
            )
        tenant_b_record = json.loads(tenant_b_probe.stdout)
        if tenant_b_record.get("status") != "passed":
            raise RuntimeError("tenant B isolation evidence did not pass")
        evidence["tenant_a_namespace_ids"] = tenant_a_record["namespace_ids"]
        evidence["tenant_b_probe"] = tenant_b_record
        evidence["concurrent_cross_tenant_isolation"] = True
        evidence["cross_tenant_profile_reuse_denied"] = True
        evidence["namespace_escape_probes_passed"] = all(
            tenant_b_record.get(key) is True
            for key in (
                "mount_syscall_denied",
                "privilege_escalation_denied",
                "foreign_pid_ptrace_denied",
            )
        )
        tenant_a_probe.terminate()
        try:
            tenant_a_probe.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tenant_a_probe.kill()
            tenant_a_probe.wait(timeout=5)
        if tenant_a_probe.stdout is not None:
            tenant_a_probe.stdout.close()
        if tenant_a_probe.stderr is not None:
            tenant_a_probe.stderr.close()
        tenant_a_probe = None
        evidence["status"] = "passed"
    except BaseException as exc:
        evidence["status"] = "failed"
        evidence["failure_type"] = type(exc).__name__
        evidence["failure_message"] = str(exc)[:512]
        if isinstance(exc, subprocess.CalledProcessError):
            evidence["failure_stdout"] = (exc.stdout or "")[-2000:]
            evidence["failure_stderr"] = (exc.stderr or "")[-4000:]
        proxy_log_path = locals().get("proxy_log")
        if isinstance(proxy_log_path, Path) and proxy_log_path.exists():
            evidence["proxy_log_tail"] = proxy_log_path.read_text(
                encoding="utf-8", errors="replace"
            )[-4000:]
        raise
    finally:
        cleanup_errors: list[str] = []
        if tenant_a_probe is not None and tenant_a_probe.poll() is None:
            tenant_a_probe.terminate()
            try:
                tenant_a_probe.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tenant_a_probe.kill()
                tenant_a_probe.wait(timeout=5)
        if tenant_a_probe is not None:
            if tenant_a_probe.stdout is not None:
                tenant_a_probe.stdout.close()
            if tenant_a_probe.stderr is not None:
                tenant_a_probe.stderr.close()
        if proxy_process is not None:
            proxy_process.terminate()
            try:
                proxy_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy_process.kill()
                proxy_process.wait(timeout=5)
        if listener is not None:
            listener.close()
        if listener_thread is not None:
            listener_thread.join(timeout=1)
        for netns in reversed(namespaces):
            listed = subprocess.run(
                ["ip", "netns", "pids", netns], check=False, capture_output=True, text=True
            )
            for raw_pid in listed.stdout.split():
                with contextlib.suppress(ProcessLookupError):
                    os.kill(int(raw_pid), signal.SIGTERM)
            if listed.stdout.strip():
                for raw_pid in listed.stdout.split():
                    with contextlib.suppress(ProcessLookupError):
                        os.kill(int(raw_pid), signal.SIGTERM)
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    remaining = subprocess.run(
                        ["ip", "netns", "pids", netns], check=False, capture_output=True, text=True
                    )
                    if not remaining.stdout.strip():
                        break
                    for raw_pid in remaining.stdout.split():
                        with contextlib.suppress(ProcessLookupError):
                            os.kill(int(raw_pid), signal.SIGKILL)
                    time.sleep(0.1)
                remaining = subprocess.run(
                    ["ip", "netns", "pids", netns], check=False, capture_output=True, text=True
                )
                if remaining.stdout.strip():
                    remaining_pids = remaining.stdout.strip()[:500]
                    cleanup_errors.append(
                        f"network namespace {netns} still has processes: {remaining_pids}"
                    )
            deleted = subprocess.run(
                ["ip", "netns", "del", netns], check=False, capture_output=True, text=True
            )
            if deleted.returncode != 0:
                cleanup_errors.append(
                    f"network namespace {netns} could not be deleted: {deleted.stderr[-500:]}"
                )
        if host_link_created:
            existing_link = subprocess.run(
                ["ip", "link", "show", "dev", host_uplink_if],
                check=False,
                capture_output=True,
            )
            if existing_link.returncode != 0:
                # Deleting the proxy namespace may already have destroyed its veth peer.
                host_link_deleted = True
            else:
                deleted = subprocess.run(
                    ["ip", "link", "del", host_uplink_if],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                host_link_deleted = deleted.returncode == 0
                if not host_link_deleted:
                    cleanup_errors.append(
                        f"proxy host uplink could not be deleted: {deleted.stderr[-500:]}"
                    )
        remaining_namespaces = {
            line.split()[0] for line in run(["ip", "netns", "list"]).splitlines() if line.split()
        }
        if host_rules_created:
            if proxy_ns in remaining_namespaces or not host_link_deleted:
                cleanup_errors.append(
                    "host egress firewall retained because proxy namespace teardown was incomplete"
                )
            else:
                for family, table in (("inet", host_forward_table), ("ip", host_nat_table)):
                    deleted = subprocess.run(
                        ["nft", "delete", "table", family, table],
                        check=False,
                        capture_output=True,
                    )
                    if deleted.returncode != 0:
                        cleanup_errors.append(f"host firewall table {table} could not be deleted")
        if host_iptables_chain is not None:
            for rule in reversed(host_iptables_rules):
                deleted = subprocess.run(
                    ["iptables", "-D", host_iptables_chain, *rule],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if deleted.returncode != 0:
                    cleanup_errors.append(
                        f"host forwarding rule could not be removed from {host_iptables_chain}"
                    )
        if resolv_dir.exists():
            shutil.rmtree(resolv_dir, ignore_errors=True)
            if resolv_dir.exists():
                cleanup_errors.append("proxy namespace resolver config remains")
        try:
            forwarding_setting = Path("/proc/sys/net/ipv4/ip_forward")
            forwarding_setting.write_text(old_forward, encoding="ascii")
            if forwarding_setting.read_text(encoding="ascii").strip() != old_forward:
                cleanup_errors.append("host IPv4 forwarding sysctl was not restored")
        except OSError:
            cleanup_errors.append("host IPv4 forwarding sysctl could not be restored")
        for family, table in (("inet", host_forward_table), ("ip", host_nat_table)):
            if (
                subprocess.run(
                    ["nft", "list", "table", family, table], check=False, capture_output=True
                ).returncode
                == 0
            ):
                cleanup_errors.append(f"host firewall table {table} remains")
        shutil.rmtree(work, ignore_errors=True)
        if work.exists():
            cleanup_errors.append("temporary browser workspace could not be removed")
        for username in users:
            deleted_user = subprocess.run(["userdel", username], check=False, capture_output=True)
            if (
                deleted_user.returncode != 0
                or subprocess.run(
                    ["getent", "passwd", username],
                    check=False,
                    capture_output=True,
                ).returncode
                == 0
            ):
                cleanup_errors.append(f"temporary browser user {username} could not be deleted")
            subprocess.run(["groupdel", username], check=False, capture_output=True)
            if (
                subprocess.run(
                    ["getent", "group", username],
                    check=False,
                    capture_output=True,
                ).returncode
                == 0
            ):
                cleanup_errors.append(f"temporary browser group {username} could not be deleted")
        evidence["cleanup_verified"] = not cleanup_errors
        if cleanup_errors:
            evidence["status"] = "failed"
            evidence["cleanup_errors"] = cleanup_errors
        artifacts.mkdir(parents=True, exist_ok=True)
        (artifacts / "browser-w4.json").write_text(
            json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        if cleanup_errors:
            raise RuntimeError(f"W4 cleanup failed: {cleanup_errors}")

    if evidence["status"] != "passed" or evidence["cleanup_verified"] is not True:
        raise RuntimeError("W4 adversarial browser isolation acceptance failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
