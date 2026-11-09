"""Read-only FCP-03 AWS egress topology preflight checks.

This module evaluates an already-collected inventory snapshot. It never calls AWS,
changes infrastructure, or treats a passing static snapshot as live enforcement proof.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from typing import Any


def _object(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _strings(value: object) -> set[str]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return {item for item in value if isinstance(item, str) and item}
    return set()


def _has_unrestricted_egress(rules: object) -> bool:
    if not isinstance(rules, Sequence) or isinstance(rules, (str, bytes)):
        return True

    for raw_rule in rules:
        rule = _object(raw_rule)
        cidr = rule.get("cidr")
        protocol = rule.get("protocol")
        port = rule.get("port")
        if not isinstance(cidr, str):
            return True
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return True
        if network.prefixlen == 0 and (network.version == 6 or protocol != "tcp" or port != 443):
            return True
    return False


def evaluate_fcp03_topology(snapshot: Mapping[str, object]) -> tuple[str, ...]:
    """Return stable finding codes for an unsafe or incomplete worker egress topology.

    An empty tuple means only that the supplied snapshot satisfies these static
    invariants. It is not a substitute for packet-level AWS enforcement probes.
    """
    findings: set[str] = set()
    worker = _object(snapshot.get("worker"))
    firewall = _object(snapshot.get("firewall"))
    policy = _object(firewall.get("policy"))
    validation = _object(policy.get("route53_resolved_ip_validation"))
    dns_firewall = _object(snapshot.get("dns_firewall"))

    if policy.get("status") != "ACTIVE":
        findings.add("firewall-policy-not-active")
    policy_errors = policy.get("errors")
    if policy_errors is None:
        findings.add("firewall-policy-errors-unknown")
    elif policy_errors:
        findings.add("firewall-policy-errors-present")
    if policy.get("stateful_rule_order") != "STRICT_ORDER":
        findings.add("firewall-stateful-order-not-strict")
    if policy.get("stateful_default_actions") != ["aws:drop_strict"]:
        findings.add("firewall-stateful-default-not-drop")
    stateful_groups = policy.get("stateful_rule_groups")
    if not isinstance(stateful_groups, Sequence) or isinstance(stateful_groups, (str, bytes)):
        stateful_groups = []
    if len(stateful_groups) != 1:
        findings.add("stateful-domain-allowlist-count-invalid")
    else:
        stateful_group = _object(stateful_groups[0])
        if stateful_group.get("status") != "ACTIVE" or stateful_group.get("type") != "STATEFUL":
            findings.add("stateful-domain-rule-group-not-active")
        if stateful_group.get("rule_order") != "STRICT_ORDER":
            findings.add("stateful-domain-rule-order-not-strict")
        if stateful_group.get("generated_rules_type") != "ALLOWLIST":
            findings.add("stateful-domain-generated-rules-not-allowlist")
        required_target_types = {
            "TLS_SNI",
            "HTTP_HOST",
            "AWS_ROUTE_53_RESOLVED_DOMAIN",
        }
        if _strings(stateful_group.get("target_types")) != required_target_types:
            findings.add("stateful-domain-target-types-invalid")
        if _strings(stateful_group.get("targets")) != _strings(
            dns_firewall.get("allowlist_domains")
        ):
            findings.add("stateful-domain-targets-mismatch")

    if worker.get("public_ip"):
        findings.add("worker-public-address")
    if worker.get("map_public_ip_on_launch") is not False:
        findings.add("worker-public-subnet")
    if worker.get("metadata_endpoint_enabled") is not False:
        findings.add("worker-metadata-endpoint-enabled")
    if worker.get("metadata_tokens_required") is not True or worker.get("metadata_hop_limit") != 1:
        findings.add("worker-metadata-protection-invalid")
    if (
        worker.get("ipv6_enabled")
        or worker.get("ipv6_addresses")
        or worker.get("ipv6_default_route_target")
    ):
        findings.add("worker-ipv6-egress-enabled")

    availability_zone = worker.get("availability_zone")
    endpoints = _object(firewall.get("endpoints_by_az"))
    endpoint = endpoints.get(availability_zone) if isinstance(availability_zone, str) else None
    if (
        not isinstance(endpoint, str)
        or not endpoint.startswith("vpce-")
        or worker.get("default_route_target") != endpoint
    ):
        findings.add("worker-firewall-route-missing")

    route_entries = worker.get("route_entries")
    if (
        not isinstance(route_entries, Sequence)
        or isinstance(route_entries, (str, bytes))
        or not route_entries
    ):
        findings.add("worker-route-inventory-unknown")
    else:
        for raw_route in route_entries:
            route = _object(raw_route)
            if not isinstance(route.get("destination"), str) or not route.get("destination"):
                findings.add("worker-route-inventory-unknown")
            if route.get("state") != "active":
                findings.add("worker-route-state-not-active")
            if route.get("target") not in {"local", endpoint}:
                findings.add("worker-route-bypasses-firewall")

    network_acl = _object(worker.get("network_acl"))
    subnet_id = worker.get("subnet_id")
    if (
        network_acl.get("associated") is not True
        or not isinstance(subnet_id, str)
        or _strings(network_acl.get("subnet_ids")) != {subnet_id}
    ):
        findings.add("worker-nacl-association-invalid")

    vpc_cidr = worker.get("vpc_cidr")
    resolver_ip = worker.get("resolver_ip")
    expected_nacl_rules: list[dict[str, object]] = []
    try:
        vpc_network = ipaddress.ip_network(vpc_cidr, strict=False)
        expected_resolver_ip = str(vpc_network.network_address + 2)
        if resolver_ip != expected_resolver_ip or vpc_network.version != 4:
            raise ValueError("VPC resolver address does not match the VPC primary CIDR")
        resolver_cidr = f"{expected_resolver_ip}/32"
        expected_nacl_rules = [
            {
                "rule_number": 90,
                "protocol": "17",
                "action": "allow",
                "cidr": resolver_cidr,
                "from_port": 53,
                "to_port": 53,
            },
            {
                "rule_number": 91,
                "protocol": "6",
                "action": "allow",
                "cidr": resolver_cidr,
                "from_port": 53,
                "to_port": 53,
            },
            {
                "rule_number": 100,
                "protocol": "-1",
                "action": "deny",
                "cidr": str(vpc_network),
                "from_port": None,
                "to_port": None,
            },
            {
                "rule_number": 110,
                "protocol": "6",
                "action": "allow",
                "cidr": "0.0.0.0/0",
                "from_port": 443,
                "to_port": 443,
            },
            {
                "rule_number": 32766,
                "protocol": "-1",
                "action": "deny",
                "cidr": "0.0.0.0/0",
                "from_port": None,
                "to_port": None,
            },
        ]
    except (TypeError, ValueError):
        findings.add("worker-nacl-egress-policy-invalid")

    raw_nacl_rules = network_acl.get("egress_rules")
    if (
        not isinstance(raw_nacl_rules, Sequence)
        or isinstance(raw_nacl_rules, (str, bytes))
        or list(raw_nacl_rules) != expected_nacl_rules
    ):
        findings.add("worker-nacl-egress-policy-invalid")

    if _has_unrestricted_egress(worker.get("security_group_egress")):
        findings.add("unrestricted-security-group-egress")

    if not validation:
        findings.add("resolved-ip-validation-missing")
    else:
        group_id = validation.get("dns_firewall_rule_group_id")
        if not isinstance(group_id, str) or group_id != dns_firewall.get("rule_group_id"):
            findings.add("resolved-ip-validation-group-mismatch")
        if validation.get("action") not in {"ALERT", "DROP"}:
            findings.add("resolved-ip-validation-action-invalid")
        if validation.get("dns_expiry_exception_action") not in {"DROP", "REJECT"}:
            findings.add("dns-expiry-not-fail-closed")
        if validation.get("bypass_destination_validation_ip_ranges") != []:
            findings.add("resolved-ip-bypass-range-present")
        source_ranges = _strings(validation.get("source_ip_ranges"))
        subnet_cidr = worker.get("subnet_cidr")
        if not isinstance(subnet_cidr, str) or subnet_cidr not in source_ranges:
            findings.add("resolved-ip-source-range-incomplete")

    worker_vpc = worker.get("vpc_id")
    associated_vpcs = _strings(dns_firewall.get("associated_vpc_ids"))
    if not isinstance(worker_vpc, str) or associated_vpcs != {worker_vpc}:
        findings.add("dns-resolution-pool-cross-vpc")
    if (
        not _strings(dns_firewall.get("allowlist_domains"))
        or dns_firewall.get("terminal_block") is not True
    ):
        findings.add("dns-allowlist-incomplete")
    if dns_firewall.get("failure_mode") != "CLOSED":
        findings.add("dns-firewall-not-fail-closed")
    if dns_firewall.get("rule_group_status") != "COMPLETE":
        findings.add("dns-rule-group-not-ready")
    association_statuses = _strings(dns_firewall.get("association_statuses"))
    if not association_statuses or association_statuses != {"COMPLETE"}:
        findings.add("dns-rule-group-association-not-ready")
    rule_statuses = _strings(dns_firewall.get("rule_statuses"))
    if not rule_statuses or rule_statuses != {"COMPLETE"}:
        findings.add("dns-firewall-rule-not-ready")
    domain_list_statuses = _strings(dns_firewall.get("domain_list_statuses"))
    if not domain_list_statuses or domain_list_statuses != {"COMPLETE"}:
        findings.add("dns-firewall-domain-list-not-ready")

    return tuple(sorted(findings))


def main(argv: list[str] | None = None) -> int:
    """Validate a normalized inventory JSON file without contacting AWS."""
    import argparse
    import json
    import sys
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--snapshot",
        default="-",
        help="normalized topology JSON path, or '-' to read standard input",
    )
    args = parser.parse_args(argv)
    try:
        raw = (
            sys.stdin.read()
            if args.snapshot == "-"
            else Path(args.snapshot).read_text(encoding="utf-8")
        )
        snapshot = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        parser.error(f"cannot read topology snapshot: {exc}")
    if not isinstance(snapshot, Mapping):
        parser.error("topology snapshot must be a JSON object")

    findings = evaluate_fcp03_topology(snapshot)
    print(
        json.dumps(
            {"status": "pass" if not findings else "fail", "findings": list(findings)},
            sort_keys=True,
        )
    )
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
