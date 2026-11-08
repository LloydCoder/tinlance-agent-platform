from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import os
import socket
import time
from pathlib import Path

from tinlance_agent_platform_sandbox.browser import (
    BrowserIsolationError,
    BrowserWorkspaceManager,
)


def chromium_process_security() -> dict[str, object]:
    """Verify Chromium's browser and renderer processes retain kernel isolation."""
    deadline = time.monotonic() + 5
    chromium: list[tuple[int, list[str], dict[str, str]]] = []
    pid_one_user_namespace = os.readlink("/proc/1/ns/user")

    while time.monotonic() < deadline:
        chromium = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal():
                continue
            pid = int(entry.name)
            command_file = entry / "cmdline"
            status_file = entry / "status"
            try:
                command = [
                    value.decode("utf-8", errors="replace")
                    for value in command_file.read_bytes().split(b"\\x00")
                    if value
                ]
                status: dict[str, str] = {}
                for line in status_file.read_text(encoding="ascii").splitlines():
                    if ":" in line:
                        key, value = line.split(":", 1)
                        status[key] = value.strip()
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            executable = command[0].lower() if command else ""
            if ("chrome" in executable or "chromium" in executable) and command:
                chromium.append((pid, command, status))

        browser_processes = [
            (pid, command, status)
            for pid, command, status in chromium
            if any(argument.startswith("--user-data-dir=") for argument in command)
            and status.get("Uid", "").split()[0:1] == [str(os.geteuid())]
        ]
        if browser_processes:
            browser_pid, browser_command, browser_status = browser_processes[0]
            renderer_processes = [
                (pid, command, status)
                for pid, command, status in chromium
                if "--type=renderer" in command
                and status.get("Uid", "").split()[0:1] == [str(os.geteuid())]
            ]
            if renderer_processes:
                break
        time.sleep(0.1)
    else:
        process_diagnostics = [
            {
                "pid": pid,
                "uid": status.get("Uid", ""),
                "command": command[:8],
            }
            for pid, command, status in chromium
        ]
        raise SystemExit(
            "Chromium did not create an isolated renderer process; "
            f"observed Chromium processes: {process_diagnostics[:12]}"
        )

    no_new_privs = browser_status.get("NoNewPrivs") == "1"
    cap_eff = browser_status.get("CapEff", "ffffffffffffffff")
    cap_eff_zero = int(cap_eff, 16) == 0
    forbidden_sandbox_flags = {
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-namespace-sandbox",
    }
    sandbox_enabled = not any(argument in forbidden_sandbox_flags for argument in browser_command)
    if not no_new_privs or not cap_eff_zero or not sandbox_enabled:
        raise SystemExit(
            "Chromium process did not retain the required sandbox/no-new-privileges boundary"
        )

    renderer_checks = []
    for renderer_pid, _, renderer_status in renderer_processes:
        renderer_user_namespace = os.readlink(f"/proc/{renderer_pid}/ns/user")
        renderer_seccomp = renderer_status.get("Seccomp") == "2"
        renderer_no_new_privs = renderer_status.get("NoNewPrivs") == "1"
        renderer_cap_eff_zero = (
            int(renderer_status.get("CapEff", "ffffffffffffffff"), 16) == 0
        )
        renderer_user_namespace_isolated = renderer_user_namespace != pid_one_user_namespace
        if not all(
            (
                renderer_seccomp,
                renderer_no_new_privs,
                renderer_cap_eff_zero,
                renderer_user_namespace_isolated,
            )
        ):
            raise SystemExit(
                "Chromium renderer lacks user-namespace, seccomp, or privilege-drop isolation"
            )
        renderer_checks.append(renderer_pid)

    return {
        "chromium_pid": browser_pid,
        "chromium_sandbox_enabled": sandbox_enabled,
        "browser_process_no_new_privs": no_new_privs,
        "browser_process_cap_eff_zero": cap_eff_zero,
        "chromium_renderer_count": len(renderer_processes),
        "chromium_renderer_seccomp_enabled": True,
        "chromium_renderer_no_new_privs": True,
        "chromium_renderer_cap_eff_zero": True,
        "chromium_renderer_user_namespace_isolated": True,
        "chromium_renderer_pids": renderer_checks,
    }

def proxy_denies(proxy_ip: str, proxy_port: int, authority: str) -> bool:
    with socket.create_connection((proxy_ip, proxy_port), timeout=3) as connection:
        connection.settimeout(3)
        connection.sendall(
            (
                f"CONNECT {authority} HTTP/1.1\r\n"
                f"Host: {authority}\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"
            ).encode("ascii")
        )
        response = connection.recv(2048)
    return b" 403 " in response.split(b"\r\n", 1)[0]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run W3 browser workspace acceptance inside its netns."
    )
    parser.add_argument("--profile-root", required=True)
    parser.add_argument("--proxy-url", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()

    proxy = urlsplit_proxy(args.proxy_url)
    proxy_ip = str(ipaddress.ip_address(proxy[0]))
    proxy_port = proxy[1]
    evidence: dict[str, object] = {
        "schema_version": 1,
        "status": "running",
        "production_certification": False,
        "browser_uid": os.geteuid(),
    }

    direct_egress_blocked = False
    try:
        socket.create_connection(("93.184.216.34", 443), timeout=2).close()
    except OSError:
        direct_egress_blocked = True
    if not direct_egress_blocked:
        raise SystemExit("direct browser-to-public-IP egress unexpectedly succeeded")
    evidence["direct_public_egress_blocked"] = True

    if not proxy_denies(proxy_ip, proxy_port, "169.254.169.254:443"):
        raise SystemExit("browser egress proxy did not reject the cloud metadata IP")
    if not proxy_denies(proxy_ip, proxy_port, "not-allowlisted.invalid:443"):
        raise SystemExit("browser egress proxy did not reject an unallowlisted hostname")
    evidence["metadata_ip_denied"] = True
    evidence["unallowlisted_hostname_denied"] = True

    manager = BrowserWorkspaceManager(
        args.profile_root,
        args.proxy_url,
        tenant_id=args.tenant_id,
        expected_uid=os.geteuid(),
    )
    first_profile: Path
    with manager.open(args.workspace_id) as session:
        response = session.navigate("https://example.com/")
        if response is None or response.status != 200:
            raise SystemExit(
                "browser could not load the allowlisted HTTPS origin through the proxy"
            )
        session.context.add_cookies(
            [
                {
                    "name": "tinlance-w3-profile-persistence",
                    "value": "verified",
                    "domain": "example.com",
                    "path": "/",
                    "secure": True,
                    "httpOnly": True,
                    "sameSite": "Lax",
                }
            ]
        )
        first_profile = session.profile_path
        browser = session.context.browser
        evidence["browser_version"] = (
            browser.version if browser is not None else "persistent-context"
        )
        evidence.update(chromium_process_security())
        evidence["allowlisted_https_navigation"] = True

    with manager.open(args.workspace_id) as resumed:
        response = resumed.navigate("https://example.com/")
        if response is None or response.status != 200:
            raise SystemExit("persistent browser workspace could not resume")
        cookies = resumed.context.cookies(["https://example.com/"])
        if not any(
            item.get("name") == "tinlance-w3-profile-persistence"
            and item.get("value") == "verified"
            for item in cookies
        ):
            raise SystemExit("browser profile cookie did not persist across workspace restart")
        evidence["profile_persisted_across_restart"] = True

    with manager.open(args.workspace_id + "-isolated") as isolated:
        isolated.navigate("https://example.com/")
        cookies = isolated.context.cookies(["https://example.com/"])
        if any(item.get("name") == "tinlance-w3-profile-persistence" for item in cookies):
            raise SystemExit("browser profile state crossed workspace boundary")
        if isolated.profile_path == first_profile:
            raise SystemExit("different workspaces reused the same browser profile directory")
        evidence["workspace_profile_isolation"] = True

    other_tenant = BrowserWorkspaceManager(
        args.profile_root,
        args.proxy_url,
        tenant_id=args.tenant_id + "-other",
        expected_uid=os.geteuid(),
    )
    try:
        other_tenant.open(args.workspace_id)
    except BrowserIsolationError:
        evidence["tenant_profile_root_binding"] = True
    else:
        raise SystemExit("a different tenant reused the same profile root")

    fail_closed_manager = BrowserWorkspaceManager(
        args.profile_root + "-failclosed",
        f"http://{proxy_ip}:{proxy_port + 1}",
        tenant_id=args.tenant_id + "-failclosed",
        expected_uid=os.geteuid(),
        navigation_timeout_ms=5_000,
    )
    proxy_unavailable_failed_closed = False
    with fail_closed_manager.open(args.workspace_id) as fail_closed_session:
        try:
            fail_closed_session.navigate("https://example.com/")
        except Exception:
            proxy_unavailable_failed_closed = True
    if not proxy_unavailable_failed_closed:
        raise SystemExit("browser did not fail closed when its configured proxy was unavailable")
    evidence["proxy_unavailable_fail_closed"] = True

    evidence["status"] = "passed"
    output = Path(args.evidence)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0


def urlsplit_proxy(value: str) -> tuple[str, int]:
    from urllib.parse import urlsplit

    parsed = urlsplit(value)
    if parsed.scheme != "http" or parsed.hostname is None or parsed.port is None:
        raise ValueError("proxy URL must be http://IP:port")
    return parsed.hostname, parsed.port


if __name__ == "__main__":
    raise SystemExit(main())
