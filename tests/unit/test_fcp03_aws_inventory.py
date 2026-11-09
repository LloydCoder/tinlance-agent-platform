from __future__ import annotations

from scripts.fcp03_aws_inventory import collect_fcp03_snapshot
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
                        "FirewallPolicyArn": "arn:aws:network-firewall:eu-west-1:123:firewall-policy/test"
                    },
                    "FirewallStatus": {
                        "Status": "READY",
                        "ConfigurationSyncStateSummary": "IN_SYNC",
                        "SyncStates": {
                            "eu-west-1a": {
                                "Attachment": {
                                    "EndpointId": "vpce-fw-a",
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
                        }
                    }
                }
            ],
        }
    )


def resolver_client() -> FakeClient:
    return FakeClient(
        {
            "list_firewall_rule_group_associations": [
                {
                    "FirewallRuleGroupAssociations": [
                        {"VpcId": "vpc-worker", "Status": "COMPLETE"}
                    ]
                }
            ],
            "list_firewall_rules": [
                {
                    "FirewallRules": [
                        {
                            "Action": "ALLOW",
                            "FirewallDomainListId": "domain-allow",
                            "Priority": 100,
                        },
                        {
                            "Action": "BLOCK",
                            "FirewallDomainListId": "domain-block",
                            "Priority": 200,
                        },
                    ]
                }
            ],
            "list_firewall_domains": [
                {"Domains": ["approved.example"]},
                {"Domains": ["*"]},
            ],
            "get_firewall_config": [
                {"FirewallConfig": {"FirewallFailOpen": "DISABLED"}}
            ],
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
    assert snapshot["dns_firewall"]["allowlist_domains"] == ["approved.example"]
    assert snapshot["dns_firewall"]["terminal_block"] is True


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

    collect_fcp03_snapshot(
        instance_id="i-test",
        ec2=ec2,
        network_firewall=firewall_client(),
        resolver=resolver_client(),
    )

    assert ec2.calls[0] == ("describe_instances", {"InstanceIds": ["i-test"]})
    assert all(not operation.startswith(("create_", "delete_", "update_", "associate_")) for operation, _ in ec2.calls)
