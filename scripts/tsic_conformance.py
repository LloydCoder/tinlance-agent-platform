#!/usr/bin/env python3
"""Fail-closed verification of the Agent Platform to TSIC integration contract."""

from __future__ import annotations

import json
from urllib.request import Request, urlopen

TSIC_REPOSITORY = "LloydCoder/tinlance-system-integration"
TSIC_REVISION = "b970805933ba80902417105389362222b3196208"
RAW_ROOT = f"https://raw.githubusercontent.com/{TSIC_REPOSITORY}/{TSIC_REVISION}"

REQUIRED_CONTRACTS = {
    "identity-context",
    "agent-registration",
    "event-envelope",
    "delivery-semantics",
    "trace-context",
    "agent-interoperability-gate",
    "economic-attribution",
}

EXPECTED_SYSTEM_REPOSITORY = "LloydCoder/tinlance-agent-platform"


def fetch_json(path: str) -> dict:
    request = Request(
        f"{RAW_ROOT}/{path}",
        headers={
            "Accept": "application/json",
            "User-Agent": "tinlance-agent-platform-ci",
        },
    )
    with urlopen(request, timeout=15) as response:
        if response.status != 200:
            raise RuntimeError(f"TSIC contract fetch failed for {path}: HTTP {response.status}")
        return json.load(response)


def main() -> None:
    manifest = fetch_json("manifests/ecosystem.json")
    adapter = fetch_json("integrations/agent-platform/adapter.json")
    registry = fetch_json("catalog/contracts/registry.json")

    systems = {item["id"]: item for item in manifest["systems"]}
    platform = systems.get("agent-platform")
    if platform is None:
        raise AssertionError("TSIC does not register Agent Platform")
    if platform["repository"] != EXPECTED_SYSTEM_REPOSITORY:
        raise AssertionError("TSIC repository mapping for Agent Platform is stale")
    if platform.get("governance_role") != "execution_authority":
        raise AssertionError("Agent Platform is not marked as the execution authority")

    if adapter["source_system"] != "tsic" or adapter["target_system"] != "agent-platform":
        raise AssertionError("TSIC Agent Platform adapter endpoints are invalid")
    if adapter["status"] != "reference-contract":
        raise AssertionError("unexpected TSIC Agent Platform adapter status")

    bindings = {item["tsic_contract"] for item in adapter["contract_bindings"]}
    if bindings != REQUIRED_CONTRACTS:
        raise AssertionError(
            "TSIC contract binding drift: "
            f"expected {sorted(REQUIRED_CONTRACTS)}, got {sorted(bindings)}"
        )

    registered = {item["id"] for item in registry["contracts"]}
    if not registered >= REQUIRED_CONTRACTS:
        raise AssertionError("TSIC contract registry is missing a required Platform contract")

    authority = adapter["authority"]
    if authority["integration_contracts"] != "tsic":
        raise AssertionError("TSIC must remain the integration-contract authority")
    for key in ("identity", "authorization", "policy", "runtime", "evidence"):
        if authority[key] != "agent-platform":
            raise AssertionError(f"Agent Platform authority drift for {key}")

    invariants = set(adapter["invariants"])
    required_invariants = {
        "adapter_never_grants_authority",
        "tenant_context_is_immutable",
        "authenticated_principal_remains_platform_authoritative",
        "consequential_operations_are_idempotent",
        "trace_context_is_preserved",
        "authoritative_evidence_remains_platform_owned",
    }
    if invariants != required_invariants:
        raise AssertionError("TSIC Agent Platform adapter invariant drift")

    print(f"PASS TSIC Agent Platform conformance: revision={TSIC_REVISION} contracts={len(bindings)}")


if __name__ == "__main__":
    main()
