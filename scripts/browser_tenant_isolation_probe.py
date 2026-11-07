from __future__ import annotations

import argparse

from tinlance_agent_platform_sandbox.browser import (
    BrowserIsolationError,
    BrowserProfileLease,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Prove another tenant UID cannot access a browser profile root.")
    parser.add_argument("--profile-root", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--workspace-id", required=True)
    args = parser.parse_args()

    try:
        lease = BrowserProfileLease.acquire(
            args.profile_root,
            args.tenant_id,
            args.workspace_id,
        )
    except (BrowserIsolationError, PermissionError):
        print("PASS: foreign tenant UID cannot acquire or traverse the profile root.")
        return 0
    else:
        lease.close()
        raise SystemExit("foreign tenant UID unexpectedly acquired another tenant's profile root")


if __name__ == "__main__":
    raise SystemExit(main())
