from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
import socket
from pathlib import Path

from tinlance_agent_platform_sandbox.browser import (
    BrowserIsolationError,
    BrowserProfileLease,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Probe concurrent tenant PID, IPC, mount, network and profile isolation."
    )
    parser.add_argument("--ipc-key", type=int, required=True)
    parser.add_argument("--hidden-host-pid", type=int, required=True)
    parser.add_argument("--proxy-host", required=True)
    parser.add_argument("--proxy-port", type=int, required=True)
    parser.add_argument("--profile-root", required=True)
    parser.add_argument("--tenant-a-namespaces", required=True)
    parser.add_argument("--host-namespaces", required=True)
    args = parser.parse_args()

    names = ("pid", "ipc", "mnt", "net")
    current = {
        name: os.stat(f"/proc/self/ns/{name}").st_ino
        for name in names
    }
    tenant_a = json.loads(args.tenant_a_namespaces)
    host = json.loads(args.host_namespaces)
    if any(current[name] == tenant_a[name] for name in names):
        raise SystemExit("tenant B shares a namespace with tenant A")
    if any(current[name] == host[name] for name in names):
        raise SystemExit("tenant B shares a namespace with the host")

    if Path(f"/proc/{args.hidden_host_pid}").exists():
        raise SystemExit("tenant B can see a foreign host PID")

    libc = ctypes.CDLL(None, use_errno=True)
    shared_memory_id = libc.shmget(args.ipc_key, 4096, 0o600)
    if shared_memory_id >= 0:
        raise SystemExit("tenant B can access tenant A's SysV shared-memory segment")
    if ctypes.get_errno() != errno.ENOENT:
        raise SystemExit("tenant B IPC probe returned an unexpected error")

    try:
        with socket.create_connection((args.proxy_host, args.proxy_port), timeout=1):
            raise SystemExit("tenant B can reach tenant A's proxy network")
    except OSError as exc:
        if exc.errno != errno.ENETUNREACH:
            raise SystemExit(
                "tenant B network denial was not caused by its isolated route table"
            ) from exc

    mount_result = libc.mount(
        ctypes.c_char_p(b"none"),
        ctypes.c_char_p(b"/tmp"),
        ctypes.c_char_p(b"tmpfs"),
        ctypes.c_ulong(0),
        ctypes.c_char_p(b"size=4k"),
    )
    if mount_result == 0:
        libc.umount2(ctypes.c_char_p(b"/tmp"), ctypes.c_int(0))
        raise SystemExit("tenant B unexpectedly mounted a filesystem")
    if ctypes.get_errno() != errno.EPERM:
        raise SystemExit("mount escape probe did not fail with EPERM")

    try:
        os.setuid(0)
    except PermissionError as exc:
        if exc.errno != errno.EPERM:
            raise SystemExit("UID escalation probe did not fail with EPERM") from exc
    else:
        raise SystemExit("tenant B unexpectedly escalated to UID 0")

    ptrace_result = libc.ptrace(16, args.hidden_host_pid, 0, 0)
    ptrace_errno = ctypes.get_errno()
    if ptrace_result == 0 or ptrace_errno not in (errno.ESRCH, errno.EPERM):
        raise SystemExit("foreign PID ptrace probe did not fail closed")

    try:
        list(Path(args.profile_root).iterdir())
    except PermissionError:
        pass
    else:
        raise SystemExit("tenant B can enumerate tenant A's profile root")

    try:
        BrowserProfileLease.acquire(
            args.profile_root,
            "phase2-w4-tenant-b",
            "workspace-a",
        )
    except (BrowserIsolationError, PermissionError):
        pass
    else:
        raise SystemExit("tenant B unexpectedly acquired tenant A's browser profile")

    print(
        json.dumps(
            {
                "status": "passed",
                "namespace_ids": current,
                "tenant_a_namespace_ids": tenant_a,
                "host_namespace_ids": host,
                "pid_namespace_isolated": True,
                "ipc_namespace_isolated": True,
                "mount_namespace_isolated": True,
                "network_namespace_isolated": True,
                "foreign_host_pid_invisible": True,
                "foreign_ipc_segment_invisible": True,
                "tenant_a_proxy_unreachable": True,
                "mount_syscall_denied": True,
                "privilege_escalation_denied": True,
                "foreign_pid_ptrace_denied": True,
                "cross_tenant_profile_reuse_denied": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
