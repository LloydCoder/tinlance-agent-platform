from __future__ import annotations

import argparse
import ctypes
import json
import os
import time


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Hold tenant A PID/IPC/mount namespaces for concurrent W4 probes."
    )
    parser.add_argument("--ipc-key", type=int, required=True)
    parser.add_argument("--hold-seconds", type=int, default=120)
    args = parser.parse_args()

    libc = ctypes.CDLL(None, use_errno=True)
    shmid = libc.shmget(args.ipc_key, 4096, 0o1000 | 0o2000 | 0o600)
    if shmid < 0:
        raise OSError(ctypes.get_errno(), "unable to create tenant A IPC marker")

    namespace_ids = {
        name: os.stat(f"/proc/self/ns/{name}").st_ino for name in ("pid", "ipc", "mnt", "net")
    }
    print(
        json.dumps(
            {"status": "ready", "namespace_ids": namespace_ids, "shared_memory_id": shmid},
            sort_keys=True,
        ),
        flush=True,
    )
    time.sleep(args.hold_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
