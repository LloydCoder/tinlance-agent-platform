# isort: skip_file
from __future__ import annotations

import json
import pathlib
import typing


TEMPLATE_PATH = (
    pathlib.Path(__file__).parents[2]
    / "infra"
    / "aws"
    / "fcp03-dns-firewall-lab"
    / "template.json"
)


def load_template() -> dict[str, typing.Any]:
    return json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))


def test_template_is_near_zero_cost_dns_firewall_only() -> None:
    template = load_template()
    resources = template["Resources"]
    types = {r["Type"] for r in resources.values()}

    # Required DNS Firewall surface
    assert "AWS::Route53Resolver::FirewallDomainList" in types
    assert "AWS::Route53Resolver::FirewallRuleGroup" in types
    assert "AWS::Route53Resolver::FirewallRuleGroupAssociation" in types
    assert "AWS::Route53Resolver::FirewallConfig" in types

    # Free Gateway Endpoints present
    assert "AWS::EC2::VPCEndpoint" in types

    # Explicitly absent expensive resources
    assert "AWS::NetworkFirewall::Firewall" not in types
    assert "AWS::NetworkFirewall::FirewallPolicy" not in types
    assert "AWS::NetworkFirewall::RuleGroup" not in types
    assert "AWS::EC2::NatGateway" not in types
    assert "AWS::EC2::EIP" not in types
    assert "AWS::EC2::InternetGateway" not in types

    # Distinct CIDR from full Network Firewall lab
    assert template["Parameters"]["VpcCidr"]["AllowedValues"] == ["10.43.0.0/16"]
    assert "Default" not in template["Parameters"]["TeardownAtUtc"]


def test_dns_firewall_is_allowlist_then_block_fail_closed() -> None:
    resources = load_template()["Resources"]
    rules = resources["DNSFirewallRuleGroup"]["Properties"]["FirewallRules"]
    assert rules[0]["Action"] == "ALLOW"
    assert rules[0]["Priority"] == 100
    assert rules[1]["Action"] == "BLOCK"
    assert rules[1]["BlockResponse"] == "NXDOMAIN"
    assert rules[1]["Priority"] == 200

    config = resources["DNSFirewallConfig"]["Properties"]
    assert config["FirewallFailOpen"] == "DISABLED"


def test_worker_has_no_public_path_no_metadata_and_dns_only_egress() -> None:
    resources = load_template()["Resources"]
    worker = resources["WorkerInstance"]["Properties"]
    subnet = resources["WorkerSubnet"]["Properties"]
    sg = resources["WorkerSecurityGroup"]["Properties"]

    assert subnet["MapPublicIpOnLaunch"] is False
    assert "Ipv6CidrBlock" not in subnet
    assert worker["MetadataOptions"]["HttpEndpoint"] == "disabled"
    assert worker["MetadataOptions"]["HttpTokens"] == "required"
    assert "IamInstanceProfile" not in worker
    assert sg.get("SecurityGroupIngress", []) == []

    egress = sg["SecurityGroupEgress"]
    protocols_ports = {(r["IpProtocol"], r["FromPort"], r["ToPort"]) for r in egress}
    assert protocols_ports == {("udp", 53, 53), ("tcp", 53, 53)}
    for rule in egress:
        assert rule["CidrIp"] == {"Fn::Sub": "${VpcCidr}"}
        assert "0.0.0.0/0" not in str(rule)


def test_nacl_denies_non_dns_egress() -> None:
    resources = load_template()["Resources"]
    deny = resources["WorkerNaclEgressDenyRest"]["Properties"]
    assert deny["RuleAction"] == "deny"
    assert deny["Egress"] is True
    assert deny["CidrBlock"] == "0.0.0.0/0"
    assert deny["Protocol"] == -1


def test_blocked_probe_must_not_be_approved_rule_exists() -> None:
    rules = load_template()["Rules"]
    assert "BlockedProbeMustNotBeApproved" in rules


def test_bootstrap_emits_structured_dns_markers() -> None:
    worker = load_template()["Resources"]["WorkerInstance"]["Properties"]
    userdata = worker["UserData"]["Fn::Base64"]["Fn::Sub"]
    assert isinstance(userdata, list)
    script = userdata[0]
    assert "FCP03_DNS_LAB_BOOTSTRAP_START" in script
    assert "FCP03_TEST_DNS_APPROVED=PASS" in script
    assert "FCP03_TEST_DNS_BLOCKED=PASS" in script
    assert "FCP03_TEST_EXTERNAL_RESOLVER=PASS" in script
    assert userdata[1]["ApprovedProbeDomain"] == {
        "Fn::Select": [0, {"Ref": "ApprovedDomains"}]
    }
    assert userdata[1]["BlockedProbeDomain"] == {"Ref": "BlockedProbeDomain"}


def test_gateway_endpoints_are_gateway_type_and_attached_to_worker_rt() -> None:
    resources = load_template()["Resources"]
    for name in ("S3GatewayEndpoint", "DynamoDBGatewayEndpoint"):
        ep = resources[name]["Properties"]
        assert ep["VpcEndpointType"] == "Gateway"
        assert ep["RouteTableIds"] == [{"Ref": "WorkerRouteTable"}]


def test_automatic_teardown_scoped_to_this_stack_only() -> None:
    resources = load_template()["Resources"]
    role_policy = resources["TeardownRole"]["Properties"]["Policies"][0]["PolicyDocument"]
    statements = role_policy["Statement"]
    assert len(statements) == 1
    assert statements[0]["Action"] == [
        "cloudformation:DeleteStack",
        "cloudformation:DescribeStacks",
    ]
    resource_arn = statements[0]["Resource"]["Fn::Sub"]
    assert "${AWS::StackName}" in resource_arn
    assert "stack/" in resource_arn

    schedule = resources["AutomaticTeardown"]["Properties"]
    assert schedule["ScheduleExpressionTimezone"] == "UTC"
    assert "deleteStack" in schedule["Target"]["Arn"]
