from __future__ import annotations

import json
from pathlib import Path
from typing import Any


TEMPLATE_PATH = (
    Path(__file__).parents[2] / "infra" / "aws" / "fcp03-egress-lab" / "template.json"
)


def load_template() -> dict[str, Any]:
    return json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))


def test_template_defines_a_single_az_disposable_fcp03_lab() -> None:
    template = load_template()
    resources = template["Resources"]

    required_types = {
        "AWS::EC2::VPC",
        "AWS::EC2::Subnet",
        "AWS::EC2::RouteTable",
        "AWS::EC2::Route",
        "AWS::EC2::NatGateway",
        "AWS::NetworkFirewall::RuleGroup",
        "AWS::NetworkFirewall::FirewallPolicy",
        "AWS::NetworkFirewall::Firewall",
        "AWS::NetworkFirewall::LoggingConfiguration",
        "AWS::Route53Resolver::FirewallDomainList",
        "AWS::Route53Resolver::FirewallRuleGroup",
        "AWS::Route53Resolver::FirewallRuleGroupAssociation",
        "AWS::Route53Resolver::FirewallConfig",
        "AWS::Scheduler::Schedule",
        "AWS::IAM::Role",
        "AWS::EC2::Instance",
    }

    assert required_types <= {resource["Type"] for resource in resources.values()}
    assert template["Parameters"]["AvailabilityZone"]["Type"] == "AWS::EC2::AvailabilityZone::Name"
    assert "Default" not in template["Parameters"]["TeardownAtUtc"]


def test_worker_has_no_public_or_ipv6_path_and_uses_firewall_default_route() -> None:
    resources = load_template()["Resources"]
    worker_subnet = resources["WorkerSubnet"]["Properties"]
    worker_instance = resources["WorkerInstance"]["Properties"]
    worker_sg = resources["WorkerSecurityGroup"]["Properties"]

    assert worker_subnet["MapPublicIpOnLaunch"] is False
    assert "Ipv6CidrBlock" not in worker_subnet
    assert "PublicIp" not in worker_instance
    assert worker_instance["MetadataOptions"]["HttpTokens"] == "required"
    assert worker_instance["MetadataOptions"]["HttpPutResponseHopLimit"] == 1
    assert worker_sg.get("SecurityGroupIngress", []) == []

    egress = worker_sg["SecurityGroupEgress"]
    world_rules = [rule for rule in egress if rule.get("CidrIp") == "0.0.0.0/0"]
    assert world_rules == [
        {
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "CidrIp": "0.0.0.0/0",
        }
    ]

    worker_route = resources["WorkerDefaultRoute"]["Properties"]
    assert worker_route["DestinationCidrBlock"] == "0.0.0.0/0"
    assert "VpcEndpointId" in worker_route
    assert "GatewayId" not in worker_route
    assert "NatGatewayId" not in worker_route

    return_route = resources["PublicReturnRoute"]["Properties"]
    assert return_route["RouteTableId"] == {"Ref": "PublicRouteTable"}
    assert return_route["DestinationCidrBlock"] == {"Ref": "WorkerSubnetCidr"}
    assert return_route["VpcEndpointId"] == worker_route["VpcEndpointId"]


def test_firewall_policy_requires_resolved_ip_validation_and_strict_domain_allowlisting() -> None:
    resources = load_template()["Resources"]
    policy = resources["FirewallPolicy"]["Properties"]["FirewallPolicy"]
    validation = policy["Route53ResolvedIPValidation"]
    rule_group = resources["ResolvedDomainRuleGroup"]["Properties"]["RuleGroup"]

    assert validation["Action"] == "DROP"
    assert validation["DNSExpiryExceptionPolicy"] == "DROP"
    assert validation["BypassDestinationValidationIPRanges"] == []
    assert validation["DNSFirewallRuleGroupId"] == {"Ref": "DNSFirewallRuleGroup"}
    assert policy["StatefulEngineOptions"]["RuleOrder"] == "STRICT_ORDER"
    assert policy["StatefulDefaultActions"] == ["aws:drop_strict"]

    rules_source = rule_group["RulesSource"]["RulesSourceList"]
    assert set(rules_source["TargetTypes"]) == {
        "TLS_SNI",
        "HTTP_HOST",
        "AWS_ROUTE_53_RESOLVED_DOMAIN",
    }
    assert rules_source["GeneratedRulesType"] == "ALLOWLIST"


def test_dns_firewall_allows_approved_domains_then_blocks_everything_else() -> None:
    resources = load_template()["Resources"]
    dns_rules = resources["DNSFirewallRuleGroup"]["Properties"]["FirewallRules"]
    ordered = sorted(dns_rules, key=lambda rule: rule["Priority"])

    assert [rule["Action"] for rule in ordered] == ["ALLOW", "BLOCK"]
    assert ordered[0]["FirewallDomainListId"] == {"Fn::GetAtt": ["ApprovedDnsDomainList", "Id"]}
    assert ordered[1]["FirewallDomainListId"] == {"Fn::GetAtt": ["WildcardDnsDomainList", "Id"]}
    assert resources["WildcardDnsDomainList"]["Properties"]["Domains"] == ["*"]
    assert resources["DNSFirewallConfig"]["Properties"]["FirewallFailOpen"] == "DISABLED"
    assert resources["DNSFirewallAssociation"]["Properties"]["MutationProtection"] == "DISABLED"


def test_lab_has_an_automatic_stack_teardown_target_scoped_to_this_stack() -> None:
    resources = load_template()["Resources"]
    schedule = resources["AutomaticTeardown"]["Properties"]
    target = schedule["Target"]
    role_policy = resources["TeardownRole"]["Properties"]["Policies"][0]["PolicyDocument"]

    assert schedule["State"] == "ENABLED"
    assert schedule["ScheduleExpression"]["Fn::Sub"] == "at(${TeardownAtUtc})"
    assert schedule["FlexibleTimeWindow"]["Mode"] == "OFF"
    assert target["Arn"] == "arn:aws:scheduler:::aws-sdk:cloudformation:deleteStack"
    assert target["Input"]["Fn::Sub"] == "{\"StackName\":\"${AWS::StackName}\"}"
    statement = role_policy["Statement"][0]
    assert statement["Action"] == ["cloudformation:DeleteStack"]
    assert statement["Resource"] == {
        "Fn::Sub": "arn:${AWS::Partition}:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/${AWS::StackName}/*"
    }


def test_lab_reuses_the_existing_ssm_instance_profile_without_widening_it() -> None:
    template = load_template()
    profile = template["Parameters"]["WorkerInstanceProfileName"]

    assert profile["Default"] == "TinlytTestRuntimeSSMProfile"
    assert template["Resources"]["WorkerInstance"]["Properties"]["IamInstanceProfile"] == {
        "Ref": "WorkerInstanceProfileName"
    }
