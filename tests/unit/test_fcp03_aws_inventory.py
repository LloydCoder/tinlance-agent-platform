from __future__ import annotations

import pytest

from scripts.fcp03_aws_inventory import _all_pages, collect_fcp03_snapshot
from scripts.fcp03_egress_preflight import evaluate_fcp03_topology


class FakeClient:
    def __init__(self, responses: dict[str, list[dict[str, object]]]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, object]]] = []

    def __getattr__(self, operation: str):
        if operation not in self.responses:
            raise AssertionError(f"unexpected AWS API operation: {operation}")

        def call(**kwargs):
            self.calls.append((operation, kwargs))
            queue = self.responses[operation]
            if not queue:
                raise AssertionError(f"unexpected extra call to {operation}")
            return queue.pop(0)

        return call


def ec2_client() -> FakeClient:
    return FakeClient(
        {
            "describe_instances": [
                {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "InstanceId": "i-test",
                                    "VpcId": "vpc-worker",
                                    "SubnetId": "subnet-worker",
                                    "Placement": {"AvailabilityZone": "eu-west-1a"},
                                    "PrivateIpAddress": "10.20.1.10",
                                    "PublicIpAddress": None,
                                    "MetadataOptions": {
                                        "HttpEndpoint": "disabled",
                                        "HttpTokens": "required",
                                        "HttpPutResponseHopLimit": 1,
                                    },
                                    "SecurityGroups": [{"GroupId": "sg-worker"}],
                                }
                            ]
                        }
                    ]
                }
            ],
            "describe_subnets": [
                {
                    "Subnets": [
                        {
                            "SubnetId": "subnet-worker",
                            "VpcId": "vpc-worker",
                            "CidrBlock": "10.20.1.0/24",
                            "MapPublicIpOnLaunch": False,
                        }
                    ]
                },
                {
                    "Subnets": [
                        {
                            "SubnetId": "subnet-firewall",
                            "VpcId": "vpc-worker",
                            "CidrBlock": "10.20.2.0/24",
                            "AvailabilityZone": "eu-west-1a",
                        }
                    ]
                },
                {
                    "Subnets": [
                        {
                            "SubnetId": "subnet-public",
                            "VpcId": "vpc-worker",
                            "CidrBlock": "10.20.3.0/24",
                            "AvailabilityZone": "eu-west-1a",
                        }
                    ]
                },
            ],
            "describe_vpcs": [
                {
                    "Vpcs": [
                        {
                            "VpcId": "vpc-worker",
                            "CidrBlock": "10.20.0.0/16",
                            "CidrBlockAssociationSet": [
                                {
                                    "CidrBlock": "10.20.0.0/16",
                                    "CidrBlockState": {"State": "associated"},
                                }
                            ],
                        }
                    ]
                }
            ],
            "describe_network_acls": [
                {
                    "NetworkAcls": [
                        {
                            "NetworkAclId": "acl-worker",
                            "Associations": [{"SubnetId": "subnet-worker"}],
                            "Entries": [
                                {
                                    "RuleNumber": 100,
                                    "Protocol": "6",
                                    "RuleAction": "allow",
                                    "Egress": False,
                                    "CidrBlock": "0.0.0.0/0",
                                    "PortRange": {"From": 1024, "To": 65535},
                                },
                                {
                                    "RuleNumber": 110,
                                    "Protocol": "17",
                                    "RuleAction": "allow",
                                    "Egress": False,
                                    "CidrBlock": "0.0.0.0/0",
                                    "PortRange": {"From": 1024, "To": 65535},
                                },
                                {
                                    "RuleNumber": 32766,
                                    "Protocol": "-1",
                                    "RuleAction": "deny",
                                    "Egress": False,
                                    "CidrBlock": "0.0.0.0/0",
                                },
                                {
                                    "RuleNumber": 90,
                                    "Protocol": "17",
                                    "RuleAction": "allow",
                                    "Egress": True,
                                    "CidrBlock": "10.20.0.2/32",
                                    "PortRange": {"From": 53, "To": 53},
                                },
                                {
                                    "RuleNumber": 91,
                                    "Protocol": "6",
                                    "RuleAction": "allow",
                                    "Egress": True,
                                    "CidrBlock": "10.20.0.2/32",
                                    "PortRange": {"From": 53, "To": 53},
                                },
                                {
                                    "RuleNumber": 100,
                                    "Protocol": "-1",
                                    "RuleAction": "deny",
                                    "Egress": True,
                                    "CidrBlock": "10.20.0.0/16",
                                },
                                {
                                    "RuleNumber": 110,
                                    "Protocol": "6",
                                    "RuleAction": "allow",
                                    "Egress": True,
                                    "CidrBlock": "0.0.0.0/0",
                                    "PortRange": {"From": 443, "To": 443},
                                },
                                {
                                    "RuleNumber": 32766,
                                    "Protocol": "-1",
                                    "RuleAction": "deny",
                                    "Egress": True,
                                    "CidrBlock": "0.0.0.0/0",
                                },
                            ],
                        }
                    ]
                }
            ],
            "describe_route_tables": [
                {
                    "RouteTables": [
                        {
                            "Associations": [{"SubnetId": "subnet-worker"}],
                            "Routes": [
                                {
                                    "DestinationCidrBlock": "0.0.0.0/0",
                                    "VpcEndpointId": "vpce-fw-a",
                                    "State": "active",
                                }
                            ],
                        }
                    ]
                },
                {
                    "RouteTables": [
                        {
                            "Associations": [{"SubnetId": "subnet-firewall"}],
                            "Routes": [
                                {
                                    "DestinationCidrBlock": "10.20.0.0/16",
                                    "GatewayId": "local",
                                    "State": "active",
                                },
                                {
                                    "DestinationCidrBlock": "0.0.0.0/0",
                                    "NatGatewayId": "nat-123",
                                    "State": "active",
                                },
                            ],
                        }
                    ]
                },
                {
                    "RouteTables": [
                        {
                            "Associations": [{"SubnetId": "subnet-public"}],
                            "Routes": [
                                {
                                    "DestinationCidrBlock": "10.20.0.0/16",
                                    "GatewayId": "local",
                                    "State": "active",
                                },
                                {
                                    "DestinationCidrBlock": "10.20.1.0/24",
                                    "VpcEndpointId": "vpce-fw-a",
                                    "State": "active",
                                },
                                {
                                    "DestinationCidrBlock": "0.0.0.0/0",
                                    "GatewayId": "igw-123",
                                    "State": "active",
                                },
                            ],
                        }
                    ]
                },
            ],
            "describe_nat_gateways": [
                {
                    "NatGateways": [
                        {
                            "NatGatewayId": "nat-123",
                            "State": "available",
                            "SubnetId": "subnet-public",
                        },
                    ]
                }
            ],
            "describe_security_groups": [
                {
                    "SecurityGroups": [
                        {
                            "GroupId": "sg-worker",
                            "IpPermissionsEgress": [
                                {
                                    "IpProtocol": "tcp",
                                    "FromPort": 443,
                                    "ToPort": 443,
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                    "Ipv6Ranges": [],
                                },
                                {
                                    "IpProtocol": "udp",
                                    "FromPort": 53,
                                    "ToPort": 53,
                                    "IpRanges": [{"CidrIp": "10.20.0.2/32"}],
                                    "Ipv6Ranges": [],
                                },
                            ],
                        }
                    ]
                }
            ],
        }
    )


def firewall_client() -> FakeClient:
    return FakeClient(
        {
            "list_firewalls": [
                {
                    "Firewalls": [
                        {
                            "FirewallArn": "arn:aws:network-firewall:eu-west-1:123:firewall/test",
                            "VpcId": "vpc-worker",
                        }
                    ]
                }
            ],
            "describe_firewall": [
                {
                    "Firewall": {
                        "FirewallPolicyArn": (
                            "arn:aws:network-firewall:eu-west-1:123:firewall-policy/test"
                        ),
                        "SubnetMappings": [{"SubnetId": "subnet-firewall"}],
                    },
                    "FirewallStatus": {
                        "Status": "READY",
                        "ConfigurationSyncStateSummary": "IN_SYNC",
                        "SyncStates": {
                            "eu-west-1a": {
                                "Attachment": {
                                    "EndpointId": "vpce-fw-a",
                                    "SubnetId": "subnet-firewall",
                                    "Status": "READY",
                                }
                            }
                        },
                    },
                }
            ],
            "describe_firewall_policy": [
                {
                    "FirewallPolicy": {
                        "Route53ResolvedIPValidation": {
                            "DNSFirewallRuleGroupId": "rslvr-frg-123",
                            "Action": "DROP",
                            "DNSExpiryExceptionPolicy": "DROP",
                            "SourceIPRanges": [{"AddressDefinition": "10.20.1.0/24"}],
                            "BypassDestinationValidationIPRanges": [],
                        },
                        "StatefulRuleGroupReferences": [
                            {
                                "ResourceArn": (
                                    "arn:aws:network-firewall:eu-west-1:123:"
                                    "stateful-rulegroup/allowlist"
                                )
                            }
                        ],
                        "StatefulEngineOptions": {"RuleOrder": "STRICT_ORDER"},
                        "StatefulDefaultActions": ["aws:drop_strict"],
                    },
                    "FirewallPolicyResponse": {"FirewallPolicyStatus": "ACTIVE", "Errors": []},
                }
            ],
            "describe_rule_group": [
                {
                    "RuleGroup": {
                        "RulesSource": {
                            "RulesSourceList": {
                                "Targets": ["approved.example"],
                                "TargetTypes": [
                                    "TLS_SNI",
                                    "HTTP_HOST",
                                    "AWS_ROUTE_53_RESOLVED_DOMAIN",
                                ],
                                "GeneratedRulesType": "ALLOWLIST",
                            }
                        },
                        "StatefulRuleOptions": {"RuleOrder": "STRICT_ORDER"},
                    },
                    "RuleGroupResponse": {"RuleGroupStatus": "ACTIVE", "Type": "STATEFUL"},
                }
            ],
        }
    )


def resolver_client() -> FakeClient:
    return FakeClient(
        {
            "describe_firewall_rule_group": [{"FirewallRuleGroup": {"Status": "COMPLETE"}}],
            "list_firewall_rule_group_associations": [
                {"FirewallRuleGroupAssociations": [{"VpcId": "vpc-worker", "Status": "COMPLETE"}]}
            ],
            "list_firewall_rules": [
                {
                    "FirewallRules": [
                        {
                            "Action": "ALLOW",
                            "FirewallDomainListId": "domain-allow",
                            "Priority": 100,
                            "Status": "COMPLETE",
                        },
                        {
                            "Action": "BLOCK",
                            "FirewallDomainListId": "domain-block",
                            "Priority": 200,
                            "Status": "COMPLETE",
                        },
                    ]
                }
            ],
            "get_firewall_domain_list": [
                {"FirewallDomainList": {"Status": "COMPLETE"}},
                {"FirewallDomainList": {"Status": "COMPLETE"}},
            ],
            "list_firewall_domains": [
                {"Domains": ["approved.example"]},
                {"Domains": ["*"]},
            ],
            "get_firewall_config": [{"FirewallConfig": {"FirewallFailOpen": "DISABLED"}}],
        }
    )


def test_collects_live_aws_shapes_into_a_preflight_snapshot() -> None:
    ec2 = ec2_client()
    firewall = firewall_client()
    resolver = resolver_client()

    snapshot = collect_fcp03_snapshot(
        instance_id="i-test",
        ec2=ec2,
        network_firewall=firewall,
        resolver=resolver,
    )

    assert evaluate_fcp03_topology(snapshot) == ()
    assert snapshot["firewall"]["endpoints_by_az"] == {"eu-west-1a": "vpce-fw-a"}
    assert snapshot["firewall"]["subnet_id"] == "subnet-firewall"
    assert snapshot["firewall"]["availability_zone"] == "eu-west-1a"
    assert snapshot["firewall"]["nat_gateway_id"] == "nat-123"
    assert snapshot["firewall"]["nat_gateway_state"] == "available"
    assert snapshot["firewall"]["nat_subnet_id"] == "subnet-public"
    assert snapshot["firewall"]["nat_availability_zone"] == "eu-west-1a"
    assert snapshot["firewall"]["route_table_subnet_ids"] == ["subnet-firewall"]
    assert snapshot["firewall"]["nat_route_table_subnet_ids"] == ["subnet-public"]
    assert snapshot["firewall"]["policy"]["stateful_rule_groups"] == [
        {
            "status": "ACTIVE",
            "type": "STATEFUL",
            "rule_order": "STRICT_ORDER",
            "generated_rules_type": "ALLOWLIST",
            "targets": ["approved.example"],
            "target_types": ["AWS_ROUTE_53_RESOLVED_DOMAIN", "HTTP_HOST", "TLS_SNI"],
        }
    ]
    assert snapshot["firewall"]["policy"]["status"] == "ACTIVE"
    assert snapshot["firewall"]["policy"]["errors"] == []
    assert snapshot["dns_firewall"]["allowlist_domains"] == ["approved.example"]
    assert snapshot["dns_firewall"]["terminal_block"] is True
    assert snapshot["worker"]["metadata_endpoint_enabled"] is False
    assert snapshot["worker"]["metadata_tokens_required"] is True
    assert snapshot["worker"]["metadata_hop_limit"] == 1
    assert snapshot["worker"]["vpc_cidr_associations"] == [
        {"cidr": "10.20.0.0/16", "state": "associated"}
    ]
    assert snapshot["worker"]["network_acl"]["subnet_ids"] == ["subnet-worker"]
    assert len(snapshot["worker"]["network_acl"]["ingress_rules"]) == 3
    assert len(snapshot["worker"]["network_acl"]["egress_rules"]) == 5
    assert snapshot["worker"]["route_entries"] == [
        {"destination": "0.0.0.0/0", "target": "vpce-fw-a", "state": "active"}
    ]


def test_missing_network_firewall_is_reported_as_incomplete_not_pass() -> None:
    ec2 = ec2_client()
    firewall = FakeClient({"list_firewalls": [{"Firewalls": []}]})
    resolver = FakeClient({})

    snapshot = collect_fcp03_snapshot(
        instance_id="i-test",
        ec2=ec2,
        network_firewall=firewall,
        resolver=resolver,
    )

    findings = evaluate_fcp03_topology(snapshot)

    assert "worker-firewall-route-missing" in findings
    assert "resolved-ip-validation-missing" in findings
    assert "dns-allowlist-incomplete" in findings


def test_collector_is_read_only_and_uses_the_requested_instance_id() -> None:
    ec2 = ec2_client()
    firewall = firewall_client()
    resolver = resolver_client()

    collect_fcp03_snapshot(
        instance_id="i-test",
        ec2=ec2,
        network_firewall=firewall,
        resolver=resolver,
    )

    assert ec2.calls[0] == ("describe_instances", {"InstanceIds": ["i-test"]})
    assert all(
        operation.startswith(("describe_", "list_", "get_"))
        for client in (ec2, firewall, resolver)
        for operation, _ in client.calls
    )


def test_rejects_dns_wildcard_block_that_precedes_allow_rules() -> None:
    resolver = resolver_client()
    resolver.responses["list_firewall_rules"][0]["FirewallRules"][1]["Priority"] = 50

    snapshot = collect_fcp03_snapshot(
        instance_id="i-test",
        ec2=ec2_client(),
        network_firewall=firewall_client(),
        resolver=resolver,
    )

    assert snapshot["dns_firewall"]["terminal_block"] is False
    assert "dns-allowlist-incomplete" in evaluate_fcp03_topology(snapshot)


def test_collector_surfaces_ipv6_addresses_and_default_routes() -> None:
    ec2 = ec2_client()
    instance = ec2.responses["describe_instances"][0]["Reservations"][0]["Instances"][0]
    instance["NetworkInterfaces"] = [{"Ipv6Addresses": [{"Ipv6Address": "2001:db8::10"}]}]
    ec2.responses["describe_subnets"][0]["Subnets"][0]["Ipv6CidrBlockAssociationSet"] = [
        {"Ipv6CidrBlock": "2001:db8:1::/64"}
    ]
    ec2.responses["describe_route_tables"][0]["RouteTables"][0]["Routes"].append(
        {
            "DestinationIpv6CidrBlock": "::/0",
            "EgressOnlyInternetGatewayId": "eigw-123",
            "State": "active",
        }
    )

    snapshot = collect_fcp03_snapshot(
        instance_id="i-test",
        ec2=ec2,
        network_firewall=firewall_client(),
        resolver=resolver_client(),
    )

    assert snapshot["worker"]["ipv6_enabled"] is True
    assert snapshot["worker"]["ipv6_addresses"] == ["2001:db8::10"]
    assert snapshot["worker"]["ipv6_default_route_target"] == "eigw-123"
    findings = evaluate_fcp03_topology(snapshot)
    assert "worker-ipv6-egress-enabled" in findings
    assert "worker-route-bypasses-firewall" in findings


def test_rejects_stateful_rule_group_without_resolved_domain_target() -> None:
    firewall = firewall_client()
    firewall.responses["describe_rule_group"][0]["RuleGroup"]["RulesSource"]["RulesSourceList"][
        "TargetTypes"
    ] = ["TLS_SNI", "HTTP_HOST"]

    snapshot = collect_fcp03_snapshot(
        instance_id="i-test",
        ec2=ec2_client(),
        network_firewall=firewall,
        resolver=resolver_client(),
    )

    assert "stateful-domain-target-types-invalid" in evaluate_fcp03_topology(snapshot)


def test_rejects_stateful_rule_group_targets_that_differ_from_dns_allowlist() -> None:
    firewall = firewall_client()
    firewall.responses["describe_rule_group"][0]["RuleGroup"]["RulesSource"]["RulesSourceList"][
        "Targets"
    ] = ["different.example"]

    snapshot = collect_fcp03_snapshot(
        instance_id="i-test",
        ec2=ec2_client(),
        network_firewall=firewall,
        resolver=resolver_client(),
    )

    assert "stateful-domain-targets-mismatch" in evaluate_fcp03_topology(snapshot)


def test_rejects_network_firewall_policy_with_async_configuration_errors() -> None:
    firewall = firewall_client()
    firewall.responses["describe_firewall_policy"][0]["FirewallPolicyResponse"]["Errors"] = [
        {"Code": "DNS_FIREWALL_RULE_GROUP_UNAVAILABLE", "Message": "DNS group unavailable"}
    ]

    snapshot = collect_fcp03_snapshot(
        instance_id="i-test",
        ec2=ec2_client(),
        network_firewall=firewall,
        resolver=resolver_client(),
    )

    assert "firewall-policy-errors-present" in evaluate_fcp03_topology(snapshot)


def test_rejects_repeated_aws_pagination_token() -> None:
    client = FakeClient(
        {
            "list_items": [
                {"Items": [{"id": "first"}], "NextToken": "repeat"},
                {"Items": [{"id": "second"}], "NextToken": "repeat"},
            ]
        }
    )

    with pytest.raises(ValueError, match="repeated pagination token"):
        _all_pages(client, "list_items", "Items")
