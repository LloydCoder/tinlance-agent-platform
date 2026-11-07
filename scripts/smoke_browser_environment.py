from __future__ import annotations

import argparse
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
import time
from pathlib import Path

PROXY_PORT = 3128


def build_child_environment(
    *,
    home: str | Path,
    tmpdir: str | Path,
    include_playwright: bool = False,
) -> dict[str, str]:
    """Pass only runtime dependencies to less-trusted browser/proxy identities."""
    allowed = {"PATH", "PYTHONPATH", "LD_LIBRARY_PATH", "LANG", "LC_ALL"}
    if include_playwright:
        allowed.add("PLAYWRIGHT_BROWSERS_PATH")
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment["HOME"] = str(home)
    environment["TMPDIR"] = str(tmpdir)
    if include_playwright:
        environment["XDG_CONFIG_HOME"] = str(Path(home) / ".config")
        environment["XDG_CACHE_HOME"] = str(Path(home) / ".cache")
    return environment


def run(
    command: list[str],
    *,
    timeout: int = 30,
    env: dict[str, str] | None = None,
) -> str:
    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    return result.stdout.strip()


def require_root() -> None:
    if os.name != "posix" or os.geteuid() != 0:
        raise SystemExit("W3 network namespace acceptance must run as root")


def create_browser_user(username: str, start_uid: int) -> tuple[int, int]:
    for uid in range(start_uid, start_uid + 1000):
        if (
            subprocess.run(
                ["getent", "passwd", str(uid)],
                check=False,
                capture_output=True,
            ).returncode
            == 0
        ):
            continue
        if (
            subprocess.run(
                ["getent", "group", str(uid)],
                check=False,
                capture_output=True,
            ).returncode
            == 0
        ):
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
                username,
            ]
        )
        return uid, int(run(["id", "-g", username]))
    raise RuntimeError("no free UID/GID available for isolated browser tenant")


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
    parser = argparse.ArgumentParser(
        description="Create and audit the W3 isolated browser network."
    )
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
    client_network = f"{guest_ip}/32"
    proxy_url = f"http://{host_ip}:{PROXY_PORT}"

    browser_user = f"tnlbr-a-{suffix}"
    proxy_user = f"tnlbr-p-{suffix}"
    other_tenant_user = f"tnlbr-b-{suffix}"
    created_users: list[str] = []
    try:
        browser_uid, browser_gid = create_browser_user(browser_user, 51_000)
        created_users.append(browser_user)
        proxy_uid, proxy_gid = create_browser_user(proxy_user, 52_000)
        created_users.append(proxy_user)
        other_tenant_uid, other_tenant_gid = create_browser_user(other_tenant_user, 53_000)
        created_users.append(other_tenant_user)
        work_root = Path(tempfile.mkdtemp(prefix="tinlance-browser-w3-"))
        profile_root = work_root / "profile"
        home_root = work_root / "home"
        tmp_root = work_root / "tmp"
        evidence_path = work_root / "guest-evidence.json"
        profile_root.mkdir(mode=0o700)
        home_root.mkdir(mode=0o700)
        tmp_root.mkdir(mode=0o700)
        for directory in (work_root, profile_root, home_root, tmp_root):
            os.chown(directory, browser_uid, browser_gid)
            os.chmod(directory, 0o700)
    except BaseException:
        for username in created_users:
            subprocess.run(["userdel", username], check=False, capture_output=True)
            subprocess.run(["groupdel", username], check=False, capture_output=True)
        raise

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
        run(
            [
                "ip",
                "netns",
                "exec",
                namespace,
                "ip",
                "addr",
                "add",
                f"{guest_ip}/30",
                "dev",
                guest_if,
            ]
        )
        run(
            [
                "ip",
                "netns",
                "exec",
                namespace,
                "sysctl",
                "-w",
                "net.ipv6.conf.all.disable_ipv6=1",
            ]
        )
        run(
            [
                "ip",
                "netns",
                "exec",
                namespace,
                "sysctl",
                "-w",
                "net.ipv6.conf.default.disable_ipv6=1",
            ]
        )
        run(
            [
                "ip",
                "netns",
                "exec",
                namespace,
                "sysctl",
                "-w",
                f"net.ipv6.conf.{guest_if}.disable_ipv6=1",
            ]
        )
        run(
            [
                "ip",
                "netns",
                "exec",
                namespace,
                "sysctl",
                "-w",
                "net.ipv6.conf.all.accept_ra=0",
            ]
        )
        run(
            [
                "ip",
                "netns",
                "exec",
                namespace,
                "sysctl",
                "-w",
                "net.ipv6.conf.default.accept_ra=0",
            ]
        )
        run(
            [
                "ip",
                "netns",
                "exec",
                namespace,
                "sysctl",
                "-w",
                f"net.ipv6.conf.{guest_if}.accept_ra=0",
            ]
        )
        run(
            [
                "ip",
                "netns",
                "exec",
                namespace,
                "sysctl",
                "-w",
                "net.ipv6.conf.lo.disable_ipv6=1",
            ]
        )
        run(["ip", "netns", "exec", namespace, "ip", "-6", "route", "flush", "default"])
        run(["ip", "netns", "exec", namespace, "ip", "link", "set", guest_if, "up"])
        run(["ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up"])
        run(
            [
                "ip",
                "netns",
                "exec",
                namespace,
                "ip",
                "-6",
                "route",
                "flush",
                "table",
                "all",
                "default",
            ]
        )
        evidence["ipv6_route_table"] = run(
            [
                "ip",
                "netns",
                "exec",
                namespace,
                "ip",
                "-6",
                "route",
                "show",
                "table",
                "all",
            ]
        )

        firewall_script = (
            f"table inet {nft_table} {{\n"
            "  chain input {\n"
            "    type filter hook input priority -50; policy accept;\n"
            f'    iifname "{host_if}" ip saddr {guest_ip} tcp dport {PROXY_PORT} accept\n'
            f'    iifname "{host_if}" drop\n'
            "  }\n"
            "}\n"
        )
        subprocess.run(
            ["nft", "-f", "-"],
            input=firewall_script,
            check=True,
            capture_output=True,
            text=True,
        )
        firewall_created = True

        routes = run(["ip", "netns", "exec", namespace, "ip", "-4", "route", "show"])
        if any(line.split()[:1] == ["default"] for line in routes.splitlines()):
            raise RuntimeError("browser network namespace unexpectedly has a default route")
        interfaces = run(["ip", "netns", "exec", namespace, "ip", "-o", "link", "show"])
        if len(interfaces.splitlines()) != 2:
            raise RuntimeError(
                "browser network namespace must contain only loopback and its proxy veth"
            )
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

        proxy_env = build_child_environment(home="/tmp", tmpdir="/tmp")
        with proxy_log.open("wb") as log_file:
            proxy_process = subprocess.Popen(
                [
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
                    host_ip,
                    "--port",
                    str(PROXY_PORT),
                    "--client-network",
                    client_network,
                    *[
                        argument
                        for domain in sorted(set(args.allowed_domain))
                        for argument in ("--allowed-domain", domain)
                    ],
                ],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                cwd=Path(__file__).resolve().parents[1],
                env=proxy_env,
                start_new_session=True,
            )
        wait_for_proxy(host_ip, PROXY_PORT, proxy_process)

        guest_command = [
            "ip",
            "netns",
            "exec",
            namespace,
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
            proxy_url,
            "--tenant-id",
            "phase2-w3-tenant-a",
            "--workspace-id",
            "workspace-a",
            "--evidence",
            str(evidence_path),
        ]
        guest_env = build_child_environment(
            home=home_root,
            tmpdir=tmp_root,
            include_playwright=True,
        )
        run(guest_command, timeout=180, env=guest_env)
        guest_evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        if guest_evidence.get("status") != "passed":
            raise RuntimeError("browser guest acceptance did not report passed")
        evidence["guest"] = guest_evidence
        evidence["proxy_process_uid"] = proxy_uid
        evidence["browser_process_uid"] = browser_uid
        evidence["other_tenant_uid"] = other_tenant_uid

        tenant_probe = [
            "setpriv",
            "--reuid",
            str(other_tenant_uid),
            "--regid",
            str(other_tenant_gid),
            "--clear-groups",
            "--no-new-privs",
            sys.executable,
            "scripts/browser_tenant_isolation_probe.py",
            "--profile-root",
            str(profile_root),
            "--tenant-id",
            "phase2-w3-tenant-b",
            "--workspace-id",
            "workspace-a",
        ]
        probe_env = build_child_environment(home="/tmp", tmpdir="/tmp")
        run(tenant_probe, timeout=15, env=probe_env)
        evidence["tenant_uid_separation"] = True
        evidence["status"] = "passed"

    except BaseException as exc:
        evidence["status"] = "failed"
        evidence["failure_type"] = type(exc).__name__
        evidence["failure_message"] = str(exc)[:512]
        if isinstance(exc, subprocess.CalledProcessError):
            if exc.stdout:
                evidence["failure_stdout"] = str(exc.stdout)[-4_000:]
            if exc.stderr:
                evidence["failure_stderr"] = str(exc.stderr)[-4_000:]
        if proxy_log.is_file():
            evidence["proxy_log_tail"] = proxy_log.read_text(encoding="utf-8", errors="replace")[
                -2_000:
            ]
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
        if firewall_created:
            deleted = subprocess.run(
                ["nft", "delete", "table", "inet", nft_table],
                check=False,
                capture_output=True,
            )
            if deleted.returncode != 0:
                cleanup_errors.append("nftables browser table could not be deleted")
        if link_created:
            deleted = subprocess.run(
                ["ip", "link", "del", host_if],
                check=False,
                capture_output=True,
            )
            if deleted.returncode != 0:
                cleanup_errors.append("browser host veth could not be deleted")
        if namespace_created:
            listed_pids = subprocess.run(
                ["ip", "netns", "pids", namespace],
                check=False,
                capture_output=True,
                text=True,
            )
            for raw_pid in listed_pids.stdout.split():
                with contextlib.suppress(ProcessLookupError):
                    os.kill(int(raw_pid), signal.SIGTERM)
            if listed_pids.stdout.strip():
                time.sleep(1)
                remaining = subprocess.run(
                    ["ip", "netns", "pids", namespace],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                for raw_pid in remaining.stdout.split():
                    with contextlib.suppress(ProcessLookupError):
                        os.kill(int(raw_pid), signal.SIGKILL)
            deleted = subprocess.run(
                ["ip", "netns", "del", namespace],
                check=False,
                capture_output=True,
            )
            if deleted.returncode != 0:
                cleanup_errors.append("browser network namespace could not be deleted")
        if (
            firewall_created
            and subprocess.run(
                ["nft", "list", "table", "inet", nft_table],
                check=False,
                capture_output=True,
            ).returncode
            == 0
        ):
            cleanup_errors.append("browser nftables table remains after cleanup")
        if namespace_created and namespace in {
            line.split()[0] for line in run(["ip", "netns", "list"]).splitlines() if line.split()
        }:
            cleanup_errors.append("browser network namespace remains after cleanup")
        if (
            link_created
            and subprocess.run(
                ["ip", "link", "show", host_if],
                check=False,
                capture_output=True,
            ).returncode
            == 0
        ):
            cleanup_errors.append("browser host veth remains after cleanup")
        evidence["cleanup_verified"] = not cleanup_errors
        if cleanup_errors:
            evidence["status"] = "failed"
            evidence["cleanup_errors"] = cleanup_errors
        output = Path(args.artifacts)
        output.mkdir(parents=True, exist_ok=True)
        (output / "browser-w3.json").write_text(
            json.dumps(evidence, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        shutil.rmtree(work_root, ignore_errors=True)
        for username in created_users:
            deleted_user = subprocess.run(
                ["userdel", username],
                check=False,
                capture_output=True,
            )
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
            subprocess.run(
                ["groupdel", username],
                check=False,
                capture_output=True,
            )
            if (
                subprocess.run(
                    ["getent", "group", username],
                    check=False,
                    capture_output=True,
                ).returncode
                == 0
            ):
                cleanup_errors.append(f"temporary browser group {username} could not be deleted")
        if cleanup_errors:
            evidence["cleanup_verified"] = False
            evidence["status"] = "failed"
            evidence["cleanup_errors"] = cleanup_errors
            output = Path(args.artifacts)
            output.mkdir(parents=True, exist_ok=True)
            (output / "browser-w3.json").write_text(
                json.dumps(evidence, sort_keys=True, indent=2) + "\\n",
                encoding="utf-8",
            )
        if cleanup_errors and evidence.get("failure_type") is None:
            raise RuntimeError(f"W3 cleanup failed: {cleanup_errors}")


if __name__ == "__main__":
    raise SystemExit(main())
