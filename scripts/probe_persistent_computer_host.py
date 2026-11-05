#!/usr/bin/env python3
"""Emit a read-only capability report for the Phase 2 compute-host gate."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from tinlance_agent_platform_sandbox.host_capabilities import (
    probe_host_capabilities,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = probe_host_capabilities().to_dict()
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if not report["microvm_ready"]:
        print("PHASE2_HOST_GATE=BLOCKED: KVM-backed microVM execution is unavailable")
    else:
        print("PHASE2_HOST_GATE=READY: KVM-backed microVM prerequisites detected")


if __name__ == "__main__":
    main()
