from __future__ import annotations

from copy import deepcopy

from scripts.fcp03_egress_preflight import evaluate_fcp03_topology


def valid_topology() -> dict[str, object]:
    return {
        "worker": {
            "vpc_id": "vpc-worker-a",
            "subnet_id": "subnet-worker-a",
            "vpc_cidr": "10.20.0.0/16",
            "vpc_cidr_associations": [
                {"cidr": "10.20.0.0/16", "state": "associated"}
            ],
            "resolver_ip": "10.20.0.2",
            "subnet_cidr": "10.20.1.0/24",
            "network_acl": {
                "associated": True,
                "subnet_ids": ["subnet-worker-a"],
                "ingress_rules": [
                    {
                        "rule_number": 100,
                        "protocol": "6",
                        "action": "allow",
                        "cidr": "0.0.0.0/0",
                        "from_port": 1024,
                        "to_port": 65535,
                    },
                    {
                        "rule_number": 110,
                        "protocol": "17",
                        "action": "allow",
                        "cidr": "0.0.0.0/0",
                        "from_port": 1024,
                        "to_port": 65535,
                    },
                    {
                        "rule_number": 32766,
                        "protocol": "-1",
                        "action": "deny",
                        "cidr": "0.0.0.0/0",
                        "from_port": None,
                        "to_port": None,
                    },
                ],
                "egress_rules": [
                    {
                        "rule_number": 90,
                        "protocol": "17",
                        "action": "allow",
                        "cidr": "10.20.0.2/32",
                        "from_port": 53,
                        "to_port": 53,
                    },
                    {
                        "rule_number": 91,
                        "protocol": "6",
                        "action": "allow",
                        "cidr": "10.20.0.2/32",
                        "from_port": 53,
                        "to_port": 53,
                    },
                    {
                        "rule_number": 100,
                        "protocol": "-1",
                        "action": "deny",
                        "cidr": "10.20.0.0/16",
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
                ],
            },
            "public_ip": None,
            "map_public_ip_on_launch": False,
            "metadata_endpoint_enabled": False,
            "metadata_tokens_required": True,
            "metadata_hop_limit": 1,
            "availability_zone": "eu-west-1a",
            "default_route_target": "vpce-fw-a",
            "route_entries": [
                {"destination": "10.20.0.0/16", "target": "local", "state": "active"},
                {"destination": "0.0.0.0/0", "target": "vpce-fw-a", "state": "active"},
            ],
            "security_group_egress": [
                {"protocol": "tcp", "port": 443, "cidr": "10.20.10.0/24"},
                {"protocol": "udp", "port": 53, "cidr": "10.20.0.2/32"},
                {"protocol": "tcp", "port": 53, "cidr": "10.20.0.2/32"},
            ],
        },
        "firewall": {
            "endpoints_by_az": {"eu-west-1a": "vpce-fw-a"},
            "policy": {
                "route53_resolved_ip_validation": {
                    "dns_firewall_rule_group_id": "rslvr-frg-123",
                    "action": "DROP",
                    "dns_expiry_exception_action": "DROP",
                    "source_ip_ranges": ["10.20.1.0/24"],
                    "bypass_destination_validation_ip_ranges": [],
                },
                "status": "ACTIVE",
                "errors": [],
                "stateful_rule_order": "STRICT_ORDER",
                "stateful_default_actions": ["aws:drop_strict"],
                "stateful_rule_groups": [
                    {
                        "status": "ACTIVE",
                        "type": "STATEFUL",
                        "rule_order": "STRICT_ORDER",
                        "generated_rules_type": "ALLOWLIST",
                        "targets": ["approved.example"],
                        "target_types": [
                            "AWS_ROUTE_53_RESOLVED_DOMAIN",
                            "HTTP_HOST",
                            "TLS_SNI",
                        ],
                    }
                ],
            },
        },
        "dns_firewall": {
            "rule_group_id": "rslvr-frg-123",
            "associated_vpc_ids": ["vpc-worker-a"],
            "allowlist_domains": ["approved.example"],
            "terminal_block": True,
            "failure_mode": "CLOSED",
            "rule_group_status": "COMPLETE",
            "association_statuses": ["COMPLETE"],
            "rule_statuses": ["COMPLETE", "COMPLETE"],
            "domain_list_statuses": ["COMPLETE", "COMPLETE"],
        },
    }


def test_accepts_a_private_worker_with_same_az_firewall_route_and_scoped_dns_policy() -> None:
    assert evaluate_fcp03_topology(valid_topology()) == ()


def test_rejects_public_worker_address_or_public_subnet_mapping() -> None:
    topology = valid_topology()
    topology["worker"]["public_ip"] = "203.0.113.10"
    topology["worker"]["map_public_ip_on_launch"] = True

    findings = evaluate_fcp03_topology(topology)

    assert "worker-public-address" in findings
    assert "worker-public-subnet" in findings


def test_rejects_default_route_that_bypasses_the_same_az_firewall_endpoint() -> None:
    topology = valid_topology()
    topology["worker"]["default_route_target"] = "igw-123"

    assert "worker-firewall-route-missing" in evaluate_fcp03_topology(topology)


def test_rejects_unrestricted_ipv4_and_ipv6_security_group_egress() -> None:
    topology = valid_topology()
    topology["worker"]["security_group_egress"].extend(
        [
            {"protocol": "-1", "port": None, "cidr": "0.0.0.0/0"},
            {"protocol": "-1", "port": None, "cidr": "::/0"},
        ]
    )

    findings = evaluate_fcp03_topology(topology)

    assert "unrestricted-security-group-egress" in findings


def test_requires_policy_level_resolved_ip_validation_and_exact_dns_group_binding() -> None:
    topology = valid_topology()
    topology["firewall"]["policy"]["route53_resolved_ip_validation"] = None

    findings = evaluate_fcp03_topology(topology)

    assert "resolved-ip-validation-missing" in findings


def test_rejects_shared_dns_resolution_pool_and_non_fail_closed_dns_policy() -> None:
    topology = valid_topology()
    topology["dns_firewall"]["associated_vpc_ids"] = ["vpc-worker-a", "vpc-tenant-b"]
    topology["dns_firewall"]["failure_mode"] = "OPEN"

    findings = evaluate_fcp03_topology(topology)

    assert "dns-resolution-pool-cross-vpc" in findings
    assert "dns-firewall-not-fail-closed" in findings


def test_rejects_dns_policy_without_allowlist_terminal_block_or_expiry_drop() -> None:
    topology = valid_topology()
    topology["dns_firewall"]["allowlist_domains"] = []
    topology["dns_firewall"]["terminal_block"] = False
    topology["firewall"]["policy"]["route53_resolved_ip_validation"][
        "dns_expiry_exception_action"
    ] = "CONTINUE"

    findings = evaluate_fcp03_topology(topology)

    assert "dns-allowlist-incomplete" in findings
    assert "dns-expiry-not-fail-closed" in findings


def test_does_not_mutate_the_supplied_inventory_snapshot() -> None:
    topology = valid_topology()
    original = deepcopy(topology)

    evaluate_fcp03_topology(topology)

    assert topology == original


def test_rejects_world_http_and_ipv6_https_egress() -> None:
    topology = valid_topology()
    topology["worker"]["security_group_egress"].extend(
        [
            {"protocol": "tcp", "port": 80, "cidr": "0.0.0.0/0"},
            {"protocol": "tcp", "port": 443, "cidr": "::/0"},
        ]
    )

    assert "unrestricted-security-group-egress" in evaluate_fcp03_topology(topology)


def test_cli_returns_zero_and_machine_readable_pass_for_valid_snapshot(tmp_path, capsys) -> None:
    import json

    from scripts.fcp03_egress_preflight import main

    snapshot_path = tmp_path / "topology.json"
    snapshot_path.write_text(json.dumps(valid_topology()), encoding="utf-8")

    assert main(["--snapshot", str(snapshot_path)]) == 0
    assert capsys.readouterr().out == '{"findings": [], "status": "pass"}\n'


def test_cli_returns_nonzero_and_findings_for_invalid_snapshot(tmp_path, capsys) -> None:
    import json

    from scripts.fcp03_egress_preflight import main

    topology = valid_topology()
    topology["worker"]["public_ip"] = "198.51.100.20"
    snapshot_path = tmp_path / "topology.json"
    snapshot_path.write_text(json.dumps(topology), encoding="utf-8")

    assert main(["--snapshot", str(snapshot_path)]) == 1
    output = capsys.readouterr().out
    assert '"status": "fail"' in output
    assert '"worker-public-address"' in output


def test_rejects_worker_ipv6_address_or_default_route() -> None:
    topology = valid_topology()
    topology["worker"]["ipv6_enabled"] = True
    topology["worker"]["ipv6_addresses"] = ["2001:db8::10"]
    topology["worker"]["ipv6_default_route_target"] = "igw-123"

    assert "worker-ipv6-egress-enabled" in evaluate_fcp03_topology(topology)


def test_rejects_incomplete_dns_firewall_resources() -> None:
    topology = valid_topology()
    topology["dns_firewall"]["association_statuses"] = ["UPDATING"]
    topology["dns_firewall"]["rule_statuses"] = ["COMPLETE", "UPDATING"]
    topology["dns_firewall"]["domain_list_statuses"] = ["IMPORTING"]

    findings = evaluate_fcp03_topology(topology)

    assert "dns-rule-group-association-not-ready" in findings
    assert "dns-firewall-rule-not-ready" in findings
    assert "dns-firewall-domain-list-not-ready" in findings


def test_rejects_an_enabled_or_unknown_instance_metadata_endpoint() -> None:
    topology = valid_topology()
    topology["worker"]["metadata_endpoint_enabled"] = True

    assert "worker-metadata-endpoint-enabled" in evaluate_fcp03_topology(topology)

    topology["worker"]["metadata_endpoint_enabled"] = None
    assert "worker-metadata-endpoint-enabled" in evaluate_fcp03_topology(topology)


def test_requires_imdsv2_and_a_single_hop_metadata_limit() -> None:
    topology = valid_topology()
    topology["worker"]["metadata_tokens_required"] = False
    topology["worker"]["metadata_hop_limit"] = 2

    findings = evaluate_fcp03_topology(topology)

    assert "worker-metadata-protection-invalid" in findings


def test_rejects_more_specific_route_that_bypasses_firewall_endpoint() -> None:
    topology = valid_topology()
    topology["worker"]["route_entries"] = [
        {"destination": "10.20.0.0/16", "target": "local", "state": "active"},
        {"destination": "0.0.0.0/0", "target": "vpce-fw-a", "state": "active"},
        {"destination": "203.0.113.0/24", "target": "nat-123", "state": "active"},
    ]

    assert "worker-route-bypasses-firewall" in evaluate_fcp03_topology(topology)


def test_fails_closed_when_route_inventory_is_missing_or_incomplete() -> None:
    topology = valid_topology()
    topology["worker"].pop("route_entries")

    assert "worker-route-inventory-unknown" in evaluate_fcp03_topology(topology)

    topology["worker"]["route_entries"] = [
        {"destination": "0.0.0.0/0", "target": "vpce-fw-a", "state": "unknown"},
    ]
    assert "worker-route-state-not-active" in evaluate_fcp03_topology(topology)


def test_rejects_worker_nacl_that_allows_vpc_local_egress_bypass() -> None:
    topology = valid_topology()
    topology["worker"]["network_acl"] = {
        "associated": True,
        "subnet_ids": ["subnet-worker-a"],
        "egress_rules": [
            {
                "rule_number": 90,
                "protocol": "17",
                "action": "allow",
                "cidr": "10.20.0.2/32",
                "from_port": 53,
                "to_port": 53,
            },
            {
                "rule_number": 91,
                "protocol": "6",
                "action": "allow",
                "cidr": "10.20.0.2/32",
                "from_port": 53,
                "to_port": 53,
            },
            {
                "rule_number": 100,
                "protocol": "-1",
                "action": "allow",
                "cidr": "10.20.0.0/16",
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
        ],
    }
    topology["worker"]["subnet_id"] = "subnet-worker-a"
    topology["worker"]["vpc_cidr"] = "10.20.0.0/16"
    topology["worker"]["resolver_ip"] = "10.20.0.2"

    assert "worker-nacl-egress-policy-invalid" in evaluate_fcp03_topology(topology)


def test_fails_closed_when_worker_subnet_nacl_association_is_missing_or_shared() -> None:
    topology = valid_topology()
    topology["worker"]["network_acl"] = {
        "associated": False,
        "subnet_ids": [],
        "egress_rules": [],
    }
    topology["worker"]["subnet_id"] = "subnet-worker-a"

    assert "worker-nacl-association-invalid" in evaluate_fcp03_topology(topology)


def test_rejects_worker_nacl_with_missing_or_unrestricted_ingress_policy() -> None:
    topology = valid_topology()
    topology["worker"]["network_acl"]["ingress_rules"] = []

    assert "worker-nacl-ingress-policy-invalid" in evaluate_fcp03_topology(topology)

    topology["worker"]["network_acl"]["ingress_rules"] = [
        {
            "rule_number": 100,
            "protocol": "-1",
            "action": "allow",
            "cidr": "0.0.0.0/0",
            "from_port": None,
            "to_port": None,
        },
    ]

    assert "worker-nacl-ingress-policy-invalid" in evaluate_fcp03_topology(topology)


def test_rejects_secondary_or_pending_vpc_cidr_associations() -> None:
    topology = valid_topology()
    topology["worker"]["vpc_cidr_associations"].append(
        {"cidr": "10.30.0.0/16", "state": "associated"}
    )

    assert "worker-vpc-cidr-associations-invalid" in evaluate_fcp03_topology(topology)

    topology["worker"]["vpc_cidr_associations"] = [
        {"cidr": "10.20.0.0/16", "state": "associating"}
    ]

    assert "worker-vpc-cidr-associations-invalid" in evaluate_fcp03_topology(topology)
