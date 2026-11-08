from __future__ import annotations

import argparse
import signal
import threading

from tinlance_agent_platform_sandbox.egress_proxy import BrowserEgressProxy, EgressPolicy


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the restricted browser HTTPS egress proxy.")
    parser.add_argument("--bind-host", required=True)
    parser.add_argument("--port", type=int, default=3128)
    parser.add_argument("--client-network", required=True)
    parser.add_argument("--allowed-domain", action="append", required=True)
    args = parser.parse_args()

    proxy = BrowserEgressProxy(
        args.bind_host,
        args.port,
        EgressPolicy(allowed_domains=frozenset(args.allowed_domain)),
        allowed_client_network=args.client_network,
    )
    stopped = threading.Event()

    def stop(_: int, __: object) -> None:
        stopped.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    proxy.start()
    try:
        stopped.wait()
    finally:
        proxy.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
