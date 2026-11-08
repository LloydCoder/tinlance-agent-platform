from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from browser_egress_network import (
    build_host_forwarding_rules,
    build_proxy_namespace_rules,
    validate_proxy_namespace_routes,
)

PROXY_PORT = 3128
DNS_SERVER = "1.1.1.1"


def run(command: list[str], *, timeout: int = 30, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        command, check=True, capture_output=True, text=True, timeout=timeout, env=env
    )
    return result.stdout.strip()


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
        run(["useradd", "--uid", str(uid), "--user-group", "--no-create-home",
             "--shell", "/usr/sbin/nologin", name])
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
            "proxy namespace unexpectedly reached restricted destination "
            f"{destination}:{port}"
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

    browser_name = f"tnlbr-a-{suffix}"
    proxy_name = f"tnlbr-p-{suffix}"
    other_name = f"tnlbr-b-{suffix}"
    users: list[str] = []
    namespaces: list[str] = []
    host_link_created = False
    host_rules_created = False
    proxy_process: subprocess.Popen[bytes] | None = None
    listener: socket.socket | None = None
    listener_thread: threading.Thread | None = None
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

        # Browser-to-proxy traffic uses a direct veth pair; neither endpoint
        # exists in the host namespace.
        run(["ip", "link", "add", browser_if, "type", "veth", "peer", "name", proxy_browser_if])
        run(["ip", "link", "set", browser_if, "netns", browser_ns])
        run(["ip", "link", "set", proxy_browser_if, "netns", proxy_ns])
        run([
            "ip", "netns", "exec", browser_ns, "ip", "addr", "add",
            f"{browser_ip}/30", "dev", browser_if,
        ])
        run([
            "ip", "netns", "exec", proxy_ns, "ip", "addr", "add",
            f"{proxy_browser_ip}/30", "dev", proxy_browser_if,
        ])
        run(["ip", "netns", "exec", browser_ns, "ip", "link", "set", browser_if, "up"])
        run(["ip", "netns", "exec", proxy_ns, "ip", "link", "set", proxy_browser_if, "up"])

        # A second, independent veth is the proxy's only host-facing uplink.
        run(["ip", "link", "add", host_uplink_if, "type", "veth", "peer", "name", proxy_uplink_if])
        host_link_created = True
        run(["ip", "link", "set", proxy_uplink_if, "netns", proxy_ns])
        run(["ip", "addr", "add", f"{host_uplink_ip}/30", "dev", host_uplink_if])
        run(["ip", "link", "set", host_uplink_if, "up"])
        run([
            "ip", "netns", "exec", proxy_ns, "ip", "addr", "add",
            f"{proxy_uplink_ip}/30", "dev", proxy_uplink_if,
        ])
        run(["ip", "netns", "exec", proxy_ns, "ip", "link", "set", proxy_uplink_if, "up"])
        run([
            "ip", "netns", "exec", proxy_ns, "ip", "route", "add",
            "default", "via", host_uplink_ip, "dev", proxy_uplink_if,
        ])

        for netns, interfaces in (
            (browser_ns, (browser_if,)),
            (proxy_ns, (proxy_browser_if, proxy_uplink_if)),
        ):
            run(["ip", "netns", "exec", netns, "ip", "link", "set", "lo", "up"])
            run(["ip", "netns", "exec", netns, "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"])
            run([
                "ip", "netns", "exec", netns, "sysctl", "-w",
                "net.ipv6.conf.default.disable_ipv6=1",
            ])
            run(["ip", "netns", "exec", netns, "sysctl", "-w", "net.ipv6.conf.all.accept_ra=0"])
            run(["ip", "netns", "exec", netns, "sysctl", "-w", "net.ipv6.conf.default.accept_ra=0"])
            run(["ip", "netns", "exec", netns, "sysctl", "-w", "net.ipv6.conf.lo.disable_ipv6=1"])
            for interface in interfaces:
                run([
                    "ip", "netns", "exec", netns, "sysctl", "-w",
                    f"net.ipv6.conf.{interface}.disable_ipv6=1",
                ])
                run([
                    "ip", "netns", "exec", netns, "sysctl", "-w",
                    f"net.ipv6.conf.{interface}.accept_ra=0",
                ])
            run([
                "ip", "netns", "exec", netns, "ip", "-6", "route",
                "flush", "table", "all", "default",
            ])
        run(["ip", "netns", "exec", proxy_ns, "sysctl", "-w", "net.ipv4.ip_forward=0"])

        resolv_dir.mkdir(parents=True, exist_ok=False)
        (resolv_dir / "resolv.conf").write_text(
            f"nameserver {DNS_SERVER}\noptions timeout:2 attempts:1\n", encoding="ascii"
        )
        os.chmod(resolv_dir / "resolv.conf", 0o644)

        proxy_rules = build_proxy_namespace_rules(
            browser_interface=proxy_browser_if,
            uplink_interface=proxy_uplink_if,
            dns_server=DNS_SERVER,
        )
        subprocess.run(
            ["ip", "netns", "exec", proxy_ns, "nft", "-f", "-"],
            input=proxy_rules, check=True, capture_output=True, text=True,
        )
        host_rules = build_host_forwarding_rules(
            proxy_host_interface=host_uplink_if,
            proxy_subnet=str(uplink_network),
        ).replace("tnl_w4_forward", host_forward_table).replace("tnl_w4_nat", host_nat_table)
        run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        subprocess.run(
            ["nft", "-f", "-"], input=host_rules, check=True,
            capture_output=True, text=True,
        )
        host_rules_created = True

        browser_routes = run(["ip", "netns", "exec", browser_ns, "ip", "-4", "route", "show"])
        if any(line.split()[:1] == ["default"] for line in browser_routes.splitlines()):
            raise RuntimeError("browser namespace unexpectedly has a default route")
        proxy_routes = run(["ip", "netns", "exec", proxy_ns, "ip", "-4", "route", "show"])
        validate_proxy_namespace_routes(
            proxy_routes, str(browser_network), str(uplink_network), host_uplink_ip
        )
        browser_interfaces = run(["ip", "netns", "exec", browser_ns, "ip", "-o", "link", "show"])
        proxy_interfaces = run(["ip", "netns", "exec", proxy_ns, "ip", "-o", "link", "show"])
        if len(browser_interfaces.splitlines()) != 2 or len(proxy_interfaces.splitlines()) != 3:
            raise RuntimeError("browser or proxy namespace contains an unexpected interface")
        host_namespace_ids = {
            name: os.stat(f"/proc/self/ns/{name}").st_ino for name in ("pid", "ipc", "mnt")
        }
        namespace_probe = (
            "import json,os; print(json.dumps({name:os.stat('/proc/self/ns/'+name).st_ino "
            "for name in ('pid','ipc','mnt')}))"
        )
        isolated_namespace_ids = json.loads(run([
            "ip", "netns", "exec", browser_ns,
            "unshare", "--mount", "--pid", "--ipc", "--fork", "--mount-proc",
            "--propagation", "private", sys.executable, "-c", namespace_probe,
        ]))
        if any(
            isolated_namespace_ids[name] == host_namespace_ids[name]
            for name in host_namespace_ids
        ):
            raise RuntimeError(
                "browser workload did not receive distinct PID, IPC and mount namespaces"
            )
        evidence.update({
            "browser_pid_namespace_isolated": True,
            "browser_ipc_namespace_isolated": True,
            "browser_mount_namespace_isolated": True,
            "browser_namespace_ids": isolated_namespace_ids,
            "host_namespace_ids": host_namespace_ids,
        })
        evidence.update({
            "browser_namespace_has_no_default_route": True,
            "proxy_namespace_has_approved_default_route": True,
            "proxy_namespace_firewall_restrictive": True,
            "browser_namespace_route_table": browser_routes,
            "proxy_namespace_route_table": proxy_routes,
            "browser_namespace_interface_count": 2,
            "proxy_namespace_interface_count": 3,
            "proxy_namespace_dns_server": DNS_SERVER,
            "proxy_namespace_egress_policy": "public TCP/443 and approved DNS only",
            "host_forwarding_policy": (
                "proxy uplink only; established replies; TCP/443; DNS to approved resolver"
            ),
        })

        proxy_log = work / "proxy.log"
        proxy_env = child_environment(Path("/tmp"), Path("/tmp"))
        with proxy_log.open("wb") as log_file:
            proxy_process = subprocess.Popen(
                [
                    "ip", "netns", "exec", proxy_ns,
                    "unshare", "--mount", "--pid", "--ipc", "--fork", "--kill-child",
                    "--mount-proc", "--propagation", "private",
                    "setpriv", "--reuid", str(proxy_uid), "--regid", str(proxy_gid),
                    "--clear-groups", "--no-new-privs", sys.executable,
                    "scripts/browser_egress_proxy.py",
                    "--bind-host", proxy_browser_ip,
                    "--port", str(PROXY_PORT),
                    "--client-network", f"{browser_ip}/32",
                    "--allowed-domain", "example.com",
                ],
                stdout=log_file, stderr=subprocess.STDOUT,
                cwd=Path(__file__).resolve().parents[1], env=proxy_env, start_new_session=True,
            )

        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if proxy_process.poll() is not None:
                raise RuntimeError("W4 egress proxy exited before readiness")
            ready = subprocess.run(
                [
                    "ip", "netns", "exec", browser_ns, sys.executable, "-c",
                    f"import socket; s=socket.create_connection(({proxy_browser_ip!r}, "
                    f"{PROXY_PORT}), timeout=1); s.close()",
                ],
                capture_output=True, timeout=2,
            )
            if ready.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise TimeoutError("W4 egress proxy did not become reachable from browser namespace")
        evidence["proxy_process_uid"] = proxy_uid
        evidence["proxy_listener_ready"] = True

        # A hostile proxy process cannot reach host-local listeners, metadata,
        # private/link-local destinations or arbitrary non-HTTPS ports.
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host_uplink_ip, 18080))
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
        run([
            "ip", "netns", "exec", proxy_ns, "nft", "insert", "rule",
            "inet", "tnl_proxy", "output",
            "oifname", proxy_uplink_if,
            "ip", "daddr", host_uplink_ip,
            "tcp", "dport", "18080", "accept",
        ])
        output_rules = run([
            "ip", "netns", "exec", proxy_ns, "nft", "-a",
            "list", "chain", "inet", "tnl_proxy", "output",
        ])
        probe_handle = next(
            int(line.rsplit("# handle ", 1)[1])
            for line in output_rules.splitlines()
            if host_uplink_ip in line and "18080" in line and "# handle " in line
        )
        try:
            host_probe_code = (
                "import socket; s=socket.socket(); s.settimeout(1); "
                f"r=s.connect_ex(({host_uplink_ip!r}, 18080)); "
                "print('REACHED' if r == 0 else 'BLOCKED')"
            )
            host_probe = subprocess.run(
                [
                    "ip", "netns", "exec", proxy_ns, "setpriv",
                    "--reuid", str(proxy_uid), "--regid", str(proxy_gid),
                    "--clear-groups", "--no-new-privs", sys.executable,
                    "-c", host_probe_code,
                ],
                capture_output=True, text=True, timeout=4,
            )
            if host_probe.returncode != 0 or host_probe.stdout.strip() != "BLOCKED":
                raise RuntimeError("host INPUT firewall did not block a proxy-to-host connection")
            evidence["proxy_namespace_host_services_blocked"] = True
            evidence["host_local_blocked_by_host_firewall"] = True
        finally:
            run([
                "ip", "netns", "exec", proxy_ns, "nft", "delete", "rule",
                "inet", "tnl_proxy", "output", "handle", str(probe_handle),
            ])
        evidence["proxy_namespace_private_egress_blocked"] = probe_blocked(
            proxy_ns, "10.0.0.1", 443
        )
        evidence["proxy_namespace_metadata_egress_blocked"] = probe_blocked(
            proxy_ns, "169.254.169.254", 443
        )
        evidence["proxy_namespace_unapproved_port_blocked"] = probe_blocked(proxy_ns, "1.1.1.1", 80)
        if listener is not None:
            listener.close()
            listener = None
        if listener_thread is not None:
            listener_thread.join(timeout=1)

        # The browser has no default route and cannot use the proxy uplink
        # directly, even if its proxy configuration is removed or bypassed.
        direct_probe = subprocess.run(
            [
                "ip", "netns", "exec", browser_ns, "setpriv",
                "--reuid", str(browser_uid), "--regid", str(browser_gid),
                "--clear-groups", "--no-new-privs", sys.executable, "-c",
                "import socket; s=socket.socket(); s.settimeout(1); "
                "r=s.connect_ex(('1.1.1.1', 443)); "
                "print('REACHED' if r == 0 else 'BLOCKED')",
            ],
            capture_output=True, text=True, timeout=4,
        )
        if direct_probe.returncode != 0 or direct_probe.stdout.strip() != "BLOCKED":
            raise RuntimeError("browser namespace unexpectedly has direct public egress")
        evidence["browser_direct_egress_blocked"] = True

        guest_command = [
            "ip", "netns", "exec", browser_ns,
            "unshare", "--mount", "--pid", "--ipc", "--fork", "--kill-child",
            "--mount-proc", "--propagation", "private",
            "setpriv", "--reuid", str(browser_uid), "--regid", str(browser_gid),
            "--clear-groups", "--no-new-privs", sys.executable,
            "scripts/browser_workspace_guest.py",
            "--profile-root", str(profile_root),
            "--proxy-url", f"http://{proxy_browser_ip}:{PROXY_PORT}",
            "--tenant-id", "phase2-w4-tenant-a",
            "--workspace-id", "workspace-a",
            "--evidence", str(guest_evidence_path),
        ]
        run(guest_command, timeout=180, env=child_environment(home, tmpdir, playwright=True))
        guest_evidence = json.loads(guest_evidence_path.read_text(encoding="utf-8"))
        if guest_evidence.get("status") != "passed":
            raise RuntimeError("W4 Chromium guest acceptance did not pass")
        evidence["guest"] = guest_evidence
        evidence["browser_process_uid"] = browser_uid
        evidence["other_tenant_uid"] = other_uid

        tenant_probe = subprocess.run(
            ["setpriv", "--reuid", str(other_uid), "--regid", str(other_gid),
             "--clear-groups", "--no-new-privs", sys.executable,
             "scripts/browser_tenant_isolation_probe.py",
             "--profile-root", str(profile_root),
             "--tenant-id", "phase2-w4-tenant-b", "--workspace-id", "workspace-a"],
            capture_output=True, text=True, timeout=15,
            env=child_environment(Path("/tmp"), Path("/tmp")),
        )
        if tenant_probe.returncode != 0:
            raise RuntimeError("cross-tenant profile reuse probe did not complete")
        evidence["cross_tenant_profile_reuse_denied"] = True
        evidence["status"] = "passed"
    except BaseException as exc:
        evidence["status"] = "failed"
        evidence["failure_type"] = type(exc).__name__
        evidence["failure_message"] = str(exc)[:512]
        if isinstance(exc, subprocess.CalledProcessError):
            evidence["failure_stdout"] = (exc.stdout or "")[-2000:]
            evidence["failure_stderr"] = (exc.stderr or "")[-2000:]
        raise
    finally:
        cleanup_errors: list[str] = []
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
            listed = subprocess.run(["ip", "netns", "pids", netns],
                                    check=False, capture_output=True, text=True)
            for raw_pid in listed.stdout.split():
                with contextlib.suppress(ProcessLookupError):
                    os.kill(int(raw_pid), signal.SIGTERM)
            if listed.stdout.strip():
                time.sleep(0.5)
                remaining = subprocess.run(["ip", "netns", "pids", netns],
                                           check=False, capture_output=True, text=True)
                for raw_pid in remaining.stdout.split():
                    with contextlib.suppress(ProcessLookupError):
                        os.kill(int(raw_pid), signal.SIGKILL)
            deleted = subprocess.run(["ip", "netns", "del", netns],
                                      check=False, capture_output=True)
            if deleted.returncode != 0:
                cleanup_errors.append(f"network namespace {netns} could not be deleted")
        if host_link_created:
            deleted = subprocess.run(["ip", "link", "del", host_uplink_if],
                                     check=False, capture_output=True)
            if deleted.returncode != 0:
                cleanup_errors.append("proxy host uplink could not be deleted")
        if host_rules_created:
            for family, table in (("inet", host_forward_table), ("ip", host_nat_table)):
                deleted = subprocess.run(
                    ["nft", "delete", "table", family, table],
                    check=False,
                    capture_output=True,
                )
                if deleted.returncode != 0:
                    cleanup_errors.append(
                        f"host firewall table {table} could not be deleted"
                    )
        if resolv_dir.exists():
            shutil.rmtree(resolv_dir, ignore_errors=True)
            if resolv_dir.exists():
                cleanup_errors.append("proxy namespace resolver config remains")
        with contextlib.suppress(OSError):
            Path("/proc/sys/net/ipv4/ip_forward").write_text(old_forward, encoding="ascii")
        for family, table in (("inet", host_forward_table), ("ip", host_nat_table)):
            if subprocess.run(["nft", "list", "table", family, table],
                              check=False, capture_output=True).returncode == 0:
                cleanup_errors.append(f"host firewall table {table} remains")
        evidence["cleanup_verified"] = not cleanup_errors
        if cleanup_errors:
            evidence["status"] = "failed"
            evidence["cleanup_errors"] = cleanup_errors
        artifacts.mkdir(parents=True, exist_ok=True)
        (artifacts / "browser-w4.json").write_text(
            json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        shutil.rmtree(work, ignore_errors=True)
        for username in users:
            subprocess.run(["userdel", username], check=False, capture_output=True)
            subprocess.run(["groupdel", username], check=False, capture_output=True)
        if cleanup_errors:
            raise RuntimeError(f"W4 cleanup failed: {cleanup_errors}")

    if evidence["status"] != "passed" or evidence["cleanup_verified"] is not True:
        raise RuntimeError("W4 adversarial browser isolation acceptance failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
