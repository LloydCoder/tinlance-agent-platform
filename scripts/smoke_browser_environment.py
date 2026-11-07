from __future__ import annotations

import argparse
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
import time
from pathlib import Path


BROWSER_UID = 65534
PROXY_PORT = 3128


def run(command: list[str], *, timeout: int = 30) -> str:
    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result.stdout.strip()


def require_root() -> None:
    if os.name != "posix" or os.geteuid() != 0:
        raise SystemExit("W3 network namespace acceptance must run as root")


def wait_for_proxy(host: str, port: int, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("browser egress proxy exited before becoming ready")
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError("browser egress proxy did not become ready")


def main() -> int:
    parser = argparse.ArgumentParser(description="Create and audit the W3 isolated browser network.")
    parser.add_argument("--artifacts", default="artifacts")
    parser.add_argument("--allowed-domain", action="append", default=["example.com"])
    args = parser.parse_args()
    require_root()

    suffix = secrets.token_hex(4)
    namespace = f"tnlbr-{suffix}"
    host_if = f"tbho{suffix}"
    guest_if = f"tbne{suffix}"
    nft_table = f"tnlbr_{suffix}"
    subnet_octet = secrets.randbelow(256)
    subnet_base = secrets.randbelow(64) * 4
    network = ipaddress.IPv4Network(f"10.253.{subnet_octet}.{subnet_base}/30")
    host_ip = str(network.network_address + 1)
    guest_ip = str(network.network_address + 2)
    client_network = str(network)
    proxy_url = f"http://{host_ip}:{PROXY_PORT}"

    work_root = Path(tempfile.mkdtemp(prefix="tinlance-browser-w3-"))
    profile_root = work_root / "profile"
    evidence_path = work_root / "guest-evidence.json"
    profile_root.mkdir(mode=0o700)
    os.chown(work_root, BROWSER_UID, BROWSER_UID)
    os.chown(profile_root, BROWSER_UID, BROWSER_UID)
    os.chmod(work_root, 0o700)
    os.chmod(profile_root, 0o700)

    proxy_log = work_root / "proxy.log"
    proxy_process: subprocess.Popen[bytes] | None = None
    namespace_created = False
    link_created = False
    firewall_created = False
    evidence: dict[str, object] = {
        "schema_version": 1,
        "status": "running",
        "phase": "W3",
        "production_certification": False,
        "network_namespace_created": False,
        "default_route_present": None,
        "browser_network_has_only_proxy_link": False,
        "host_firewall_proxy_only": False,
        "proxy_allowlist": sorted(set(args.allowed_domain)),
    }

    try:
        run(["ip", "netns", "add", namespace])
        namespace_created = True
        run(["ip", "link", "add", host_if, "type", "veth", "peer", "name", guest_if])
        link_created = True
        run(["ip", "link", "set", guest_if, "netns", namespace])
        run(["ip", "addr", "add", f"{host_ip}/30", "dev", host_if])
        run(["ip", "link", "set", host_if, "up"])
        run(["ip", "netns", "exec", namespace, "ip", "addr", "add", f"{guest_ip}/30", "dev", guest_if])
        run(["ip", "netns", "exec", namespace, "ip", "link", "set", guest_if, "up"])
        run(["ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up"])
        run(["ip", "netns", "exec", namespace, "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"])
        run(["ip", "netns", "exec", namespace, "sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"])

        run(["nft", "add", "table", "inet", nft_table])
        run(
            [
                "nft", "add", "chain", "inet", nft_table, "input",
                "{ type filter hook input priority -50; policy accept; }",
            ]
        )
        run(
            [
                "nft", "add", "rule", "inet", nft_table, "input",
                "iifname", host_if, "ip", "saddr", guest_ip,
                "tcp", "dport", str(PROXY_PORT), "accept",
            ]
        )
        run(["nft", "add", "rule", "inet", nft_table, "input", "iifname", host_if, "drop"])
        firewall_created = True

        routes = run(["ip", "netns", "exec", namespace, "ip", "-4", "route", "show"])
        if any(line.split()[:1] == ["default"] for line in routes.splitlines()):
            raise RuntimeError("browser network namespace unexpectedly has a default route")
        interfaces = run(["ip", "netns", "exec", namespace, "ip", "-o", "link", "show"])
        if len(interfaces.splitlines()) != 2:
            raise RuntimeError("browser network namespace must contain only loopback and its proxy veth")
        evidence.update(
            {
                "network_namespace_created": True,
                "default_route_present": False,
                "browser_network_has_only_proxy_link": True,
                "host_firewall_proxy_only": True,
                "network_namespace_interface_count": 2,
                "browser_proxy_address": proxy_url,
                "browser_route_table": routes,
            }
        )

        with proxy_log.open("wb") as log_file:
            proxy_process = subprocess.Popen(
                [
                    "setpriv",
                    "--reuid",
                    str(BROWSER_UID),
                    "--regid",
                    str(BROWSER_UID),
                    "--clear-groups",
                    "--no-new-privs",
                    sys.executable,
                    "scripts/browser_egress_proxy.py",
                    "--bind-host",
                    host_ip,
                    "--port",
                    str(PROXY_PORT),
                    "--client-network",
                    client_network,
                    *sum((["--allowed-domain", domain] for domain in sorted(set(args.allowed_domain))), []),
                ],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                cwd=Path(__file__).resolve().parents[1],
                start_new_session=True,
            )
        wait_for_proxy(host_ip, PROXY_PORT, proxy_process)

        guest_command = [
            "ip", "netns", "exec", namespace,
            "setpriv",
            "--reuid", str(BROWSER_UID),
            "--regid", str(BROWSER_UID),
            "--clear-groups",
            "--no-new-privs",
            sys.executable,
            "scripts/browser_workspace_guest.py",
            "--profile-root", str(profile_root),
            "--proxy-url", proxy_url,
            "--tenant-id", "phase2-w3-tenant-a",
            "--workspace-id", "workspace-a",
            "--evidence", str(evidence_path),
        ]
        run(guest_command, timeout=180)
        guest_evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        if guest_evidence.get("status") != "passed":
            raise RuntimeError("browser guest acceptance did not report passed")
        evidence["guest"] = guest_evidence
        evidence["proxy_process_uid"] = BROWSER_UID
        evidence["browser_process_uid"] = BROWSER_UID
        evidence["status"] = "passed"

        output = Path(args.artifacts)
        output.mkdir(parents=True, exist_ok=True)
        (output / "browser-w3.json").write_text(
            json.dumps(evidence, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return 0
    finally:
        if proxy_process is not None:
            proxy_process.terminate()
            try:
                proxy_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy_process.kill()
                proxy_process.wait(timeout=5)
        if firewall_created:
            subprocess.run(
                ["nft", "delete", "table", "inet", nft_table],
                check=False,
                capture_output=True,
            )
        if link_created:
            subprocess.run(["ip", "link", "del", host_if], check=False, capture_output=True)
        if namespace_created:
            subprocess.run(["ip", "netns", "del", namespace], check=False, capture_output=True)
        shutil.rmtree(work_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
