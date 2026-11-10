# isort: skip_file
from __future__ import annotations

import json
import pathlib
import typing


TEMPLATE_PATH = (
    pathlib.Path(__file__).parents[2] / "infra" / "aws" / "fcp03-dns-firewall-lab" / "template.json"
)


def load_template() -> dict[str, typing.Any]:
    return json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))


def _userdata_script() -> str:
    worker = load_template()["Resources"]["WorkerInstance"]["Properties"]
    userdata = worker["UserData"]["Fn::Base64"]["Fn::Sub"]
    assert isinstance(userdata, list)
    return userdata[0]


def test_template_is_near_zero_cost_dns_firewall_only() -> None:
    template = load_template()
    resources = template["Resources"]
    types = {r["Type"] for r in resources.values()}

    assert "AWS::Route53Resolver::FirewallDomainList" in types
    assert "AWS::Route53Resolver::FirewallRuleGroup" in types
    assert "AWS::Route53Resolver::FirewallRuleGroupAssociation" in types
    assert "AWS::Route53Resolver::FirewallConfig" in types
    assert "AWS::EC2::VPCEndpoint" in types

    assert "AWS::NetworkFirewall::Firewall" not in types
    assert "AWS::NetworkFirewall::FirewallPolicy" not in types
    assert "AWS::NetworkFirewall::RuleGroup" not in types
    assert "AWS::EC2::NatGateway" not in types
    assert "AWS::EC2::EIP" not in types
    assert "AWS::EC2::InternetGateway" not in types

    assert template["Parameters"]["VpcCidr"]["AllowedValues"] == ["10.43.0.0/16"]
    assert template["Parameters"]["VpcResolverCidr"]["AllowedValues"] == ["10.43.0.2/32"]
    assert "Default" not in template["Parameters"]["TeardownAtUtc"]


def test_dns_firewall_is_allowlist_then_block_fail_closed() -> None:
    resources = load_template()["Resources"]
    rules = resources["DNSFirewallRuleGroup"]["Properties"]["FirewallRules"]
    assert rules[0]["Action"] == "ALLOW"
    assert rules[0]["Priority"] == 100
    assert rules[1]["Action"] == "BLOCK"
    assert rules[1]["BlockResponse"] == "NXDOMAIN"
    assert rules[1]["Priority"] == 200
    assert resources["DNSFirewallConfig"]["Properties"]["FirewallFailOpen"] == "DISABLED"


def test_dns_egress_restricted_to_vpc_resolver_not_whole_vpc() -> None:
    resources = load_template()["Resources"]
    sg_egress = resources["WorkerSecurityGroup"]["Properties"]["SecurityGroupEgress"]
    assert len(sg_egress) == 2
    for rule in sg_egress:
        assert rule["CidrIp"] == {"Ref": "VpcResolverCidr"}
        assert rule["FromPort"] == 53
        assert rule["ToPort"] == 53
        assert rule["IpProtocol"] in {"udp", "tcp"}
        assert "0.0.0.0/0" not in str(rule)
        assert rule["CidrIp"] != {"Ref": "VpcCidr"}

    for name in ("WorkerNaclEgressDnsUdp", "WorkerNaclEgressDnsTcp"):
        props = resources[name]["Properties"]
        assert props["CidrBlock"] == {"Ref": "VpcResolverCidr"}
        assert props["Egress"] is True
        assert props["PortRange"] == {"From": 53, "To": 53}


def test_nacl_has_dns_response_return_path_udp_and_tcp() -> None:
    resources = load_template()["Resources"]
    for name, proto in (("WorkerNaclIngressDnsUdp", 17), ("WorkerNaclIngressDnsTcp", 6)):
        props = resources[name]["Properties"]
        assert props["Protocol"] == proto
        assert props["Egress"] is False
        assert props["RuleAction"] == "allow"
        assert props["CidrBlock"] == {"Ref": "VpcResolverCidr"}
        assert props["PortRange"]["From"] == 1024
        assert props["PortRange"]["To"] == 65535


def test_nacl_has_vpc_local_dhcp_and_denies_broad_egress() -> None:
    resources = load_template()["Resources"]
    dhcp_e = resources["WorkerNaclEgressDhcp"]["Properties"]
    dhcp_i = resources["WorkerNaclIngressDhcp"]["Properties"]
    assert dhcp_e["Protocol"] == 17
    assert dhcp_e["CidrBlock"] == {"Ref": "VpcCidr"}
    assert dhcp_e["PortRange"] == {"From": 67, "To": 68}
    assert dhcp_i["CidrBlock"] == {"Ref": "VpcCidr"}

    deny = resources["WorkerNaclEgressDenyRest"]["Properties"]
    assert deny["RuleAction"] == "deny"
    assert deny["Egress"] is True
    assert deny["CidrBlock"] == "0.0.0.0/0"
    assert deny["Protocol"] == -1

    deny_in = resources["WorkerNaclIngressDenyRest"]["Properties"]
    assert deny_in["RuleAction"] == "deny"
    assert deny_in["Egress"] is False


def test_worker_has_no_public_path_no_metadata_no_instance_profile() -> None:
    resources = load_template()["Resources"]
    worker = resources["WorkerInstance"]["Properties"]
    subnet = resources["WorkerSubnet"]["Properties"]
    sg = resources["WorkerSecurityGroup"]["Properties"]

    assert subnet["MapPublicIpOnLaunch"] is False
    assert "Ipv6CidrBlock" not in subnet
    assert worker["MetadataOptions"]["HttpEndpoint"] == "disabled"
    assert "IamInstanceProfile" not in worker
    assert sg.get("SecurityGroupIngress", []) == []
    assert worker["BlockDeviceMappings"][0]["Ebs"]["Encrypted"] is True
    assert worker["BlockDeviceMappings"][0]["Ebs"]["DeleteOnTermination"] is True


def test_gateway_endpoint_policies_are_deny_all() -> None:
    resources = load_template()["Resources"]
    for name in ("S3GatewayEndpoint", "DynamoDBGatewayEndpoint"):
        ep = resources[name]["Properties"]
        assert ep["VpcEndpointType"] == "Gateway"
        assert ep["RouteTableIds"] == [{"Ref": "WorkerRouteTable"}]
        statements = ep["PolicyDocument"]["Statement"]
        assert len(statements) == 1
        assert statements[0]["Effect"] == "Deny"
        assert statements[0]["Action"] == "*"
        assert statements[0]["Resource"] == "*"


def test_bootstrap_rejects_false_positive_probe_logic() -> None:
    script = _userdata_script()
    assert "command -v dig" in script
    assert "INCONCLUSIVE_MISSING_DIG" in script
    assert "INCONCLUSIVE_RESOLVER_UNREACHABLE_OR_TIMEOUT" in script
    assert "NXDOMAIN" in script
    assert "NOERROR" in script
    assert "FAIL_UNEXPECTED_RESOLUTION" in script
    assert "FAIL_STATUS_" in script
    assert "getent hosts" not in script
    assert "FCP03_TEST_DNS_APPROVED=PASS" in script
    assert "FCP03_TEST_DNS_BLOCKED=PASS" in script
    assert "10.43.0.2" in script


def test_blocked_probe_must_not_be_approved_rule_exists() -> None:
    assert "BlockedProbeMustNotBeApproved" in load_template()["Rules"]


def test_automatic_teardown_scoped_to_this_stack_only() -> None:
    resources = load_template()["Resources"]
    role_policy = resources["TeardownRole"]["Properties"]["Policies"][0]["PolicyDocument"]
    statements = role_policy["Statement"]
    assert len(statements) == 1
    assert statements[0]["Action"] == [
        "cloudformation:DeleteStack",
        "cloudformation:DescribeStacks",
    ]
    assert "${AWS::StackName}" in statements[0]["Resource"]["Fn::Sub"]
    schedule = resources["AutomaticTeardown"]["Properties"]
    assert schedule["ScheduleExpressionTimezone"] == "UTC"
    assert "deleteStack" in schedule["Target"]["Arn"]


def test_no_broad_sg_or_nacl_internet_egress() -> None:
    resources = load_template()["Resources"]
    for rule in resources["WorkerSecurityGroup"]["Properties"]["SecurityGroupEgress"]:
        assert rule.get("CidrIp") != "0.0.0.0/0"
        assert "0.0.0.0/0" not in str(rule)
    for name, res in resources.items():
        if res.get("Type") != "AWS::EC2::NetworkAclEntry":
            continue
        props = res["Properties"]
        if props.get("Egress") and props.get("CidrBlock") == "0.0.0.0/0":
            assert props["RuleAction"] == "deny"
            assert name == "WorkerNaclEgressDenyRest"


def test_cloudformation_rules_reject_overlap_without_constant_false_assertions() -> None:
    rule = load_template()["Rules"]["BlockedProbeMustNotBeApproved"]
    assert "RuleCondition" not in rule
    assert rule["Assertions"][0]["Assert"] == {
        "Fn::Not": [
            {
                "Fn::Contains": [
                    {"Ref": "ApprovedDomains"},
                    {"Ref": "BlockedProbeDomain"},
                ]
            }
        ]
    }


def test_userdata_shell_defaults_do_not_collide_with_cloudformation_substitution() -> None:
    script = _userdata_script()
    assert "${APPROVED_ANS:-0}" not in script
    assert "${APPROVED_STATUS:-UNKNOWN}" not in script
    assert "${BLOCKED_STATUS}" not in script
