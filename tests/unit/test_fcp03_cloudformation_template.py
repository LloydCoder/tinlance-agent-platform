# isort: skip_file
from __future__ import annotations

import json
import pathlib
import typing


TEMPLATE_PATH = (
    pathlib.Path(__file__).parents[2] / "infra" / "aws" / "fcp03-egress-lab" / "template.json"
)


def load_template() -> dict[str, typing.Any]:
    return json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))


def test_template_defines_a_single_az_disposable_fcp03_lab() -> None:
    template = load_template()
    resources = template["Resources"]

    required_types = {
        "AWS::EC2::VPC",
        "AWS::EC2::Subnet",
        "AWS::EC2::NetworkAcl",
        "AWS::EC2::NetworkAclEntry",
        "AWS::EC2::SubnetNetworkAclAssociation",
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
    assert template["Parameters"]["VpcCidr"]["AllowedValues"] == ["10.42.0.0/16"]
    assert "ApprovedProbeDomain" not in template["Parameters"]
    assert "Default" not in template["Parameters"]["TeardownAtUtc"]


def test_worker_has_no_public_or_ipv6_path_and_uses_firewall_default_route() -> None:
    resources = load_template()["Resources"]
    worker_subnet = resources["WorkerSubnet"]["Properties"]
    worker_instance = resources["WorkerInstance"]["Properties"]
    worker_sg = resources["WorkerSecurityGroup"]["Properties"]

    assert worker_subnet["MapPublicIpOnLaunch"] is False
    assert "Ipv6CidrBlock" not in worker_subnet
    assert "PublicIp" not in worker_instance
    assert worker_instance["MetadataOptions"]["HttpEndpoint"] == "disabled"
    assert worker_instance["MetadataOptions"]["HttpTokens"] == "required"
    assert worker_instance["MetadataOptions"]["HttpPutResponseHopLimit"] == 1
    assert "IamInstanceProfile" not in worker_instance
    bootstrap = worker_instance["UserData"]["Fn::Base64"]["Fn::Sub"][0]
    assert bootstrap.find("FCP03_BOOTSTRAP_START") >= 0
    assert "FCP03_TEST_DNS_APPROVED=PASS" in bootstrap
    bootstrap = worker_instance["UserData"]["Fn::Base64"]["Fn::Sub"]
    assert isinstance(bootstrap, list)
    assert bootstrap[1] == {"ApprovedProbeDomain": {"Fn::Select": [0, {"Ref": "ApprovedDomains"}]}}
    assert "FCP03_TEST_HTTPS_APPROVED=PASS" in bootstrap[0]
    assert "FCP03_TEST_DIRECT_IP=INCONCLUSIVE_REQUIRES_FLOW_EVIDENCE" in bootstrap[0]
    assert "FCP03_TEST_DIRECT_IP=EXPECTED_BLOCK_OR_UNAVAILABLE" not in bootstrap[0]
    assert worker_sg.get("SecurityGroupIngress", []) == []

    egress = worker_sg["SecurityGroupEgress"]
    world_rules = [rule for rule in egress if rule.get("CidrIp") == "0.0.0.0/0"]
    assert world_rules == [
        {
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "CidrIp": "0.0.0.0/0",
            "Description": "HTTPS routed through Network Firewall",
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
    assert schedule["Name"] == "tinlance-fcp03-auto-teardown"
    assert schedule["FlexibleTimeWindow"]["Mode"] == "OFF"
    trust = resources["TeardownRole"]["Properties"]["AssumeRolePolicyDocument"]
    expected_schedule_arn = (
        "arn:${AWS::Partition}:scheduler:${AWS::Region}:${AWS::AccountId}:"
        "schedule/default/tinlance-fcp03-auto-teardown"
    )
    assert trust["Statement"][0]["Condition"]["ArnEquals"]["aws:SourceArn"] == {
        "Fn::Sub": expected_schedule_arn
    }
    assert target["Arn"] == "arn:aws:scheduler:::aws-sdk:cloudformation:deleteStack"
    assert target["Input"]["Fn::Sub"] == '{"StackName":"${AWS::StackName}"}'
    statement = role_policy["Statement"][0]
    assert statement["Action"] == ["cloudformation:DeleteStack"]
    expected_stack_arn = (
        "arn:${AWS::Partition}:cloudformation:${AWS::Region}:${AWS::AccountId}:"
        "stack/${AWS::StackName}/*"
    )
    assert statement["Resource"] == {"Fn::Sub": expected_stack_arn}


def test_nat_and_firewall_routes_are_symmetric_and_worker_volume_is_encrypted() -> None:
    resources = load_template()["Resources"]
    public_route = resources["PublicDefaultRoute"]["Properties"]
    firewall_route = resources["FirewallDefaultRoute"]["Properties"]
    worker = resources["WorkerInstance"]["Properties"]

    assert public_route["GatewayId"] == {"Ref": "InternetGateway"}
    assert firewall_route["NatGatewayId"] == {"Ref": "NatGateway"}
    dependencies = resources["WorkerInstance"]["DependsOn"]
    assert "PublicReturnRoute" in dependencies
    assert "AutomaticTeardown" in dependencies
    ebs = worker["BlockDeviceMappings"][0]["Ebs"]
    assert ebs["Encrypted"] is True
    assert ebs["DeleteOnTermination"] is True


def test_worker_nacl_allows_only_resolver_dns_and_inspected_https_egress() -> None:
    resources = load_template()["Resources"]
    association = resources["WorkerNetworkAclAssociation"]["Properties"]
    assert association == {
        "SubnetId": {"Ref": "WorkerSubnet"},
        "NetworkAclId": {"Ref": "WorkerNetworkAcl"},
    }
    assert set(resources["WorkerNetworkAclAssociation"]["DependsOn"]) == {
        "WorkerNaclEgressDnsUdp",
        "WorkerNaclEgressDnsTcp",
        "WorkerNaclEgressDenyVpc",
        "WorkerNaclEgressHttps",
        "WorkerNaclEgressDenyRest",
        "WorkerNaclIngressTcpEphemeral",
        "WorkerNaclIngressUdpEphemeral",
        "WorkerNaclIngressDenyRest",
    }

    entries = [
        resource["Properties"]
        for resource in resources.values()
        if resource["Type"] == "AWS::EC2::NetworkAclEntry"
    ]
    egress = sorted(
        (entry for entry in entries if entry["Egress"]),
        key=lambda entry: entry["RuleNumber"],
    )
    ingress = sorted(
        (entry for entry in entries if not entry["Egress"]),
        key=lambda entry: entry["RuleNumber"],
    )

    assert [entry["RuleNumber"] for entry in egress] == [90, 91, 100, 110, 32766]
    assert egress[0]["CidrBlock"] == "10.42.0.2/32"
    assert egress[1]["CidrBlock"] == "10.42.0.2/32"
    assert egress[2]["RuleAction"] == "deny"
    assert egress[2]["CidrBlock"] == {"Ref": "VpcCidr"}
    assert egress[3]["RuleAction"] == "allow"
    assert egress[3]["Protocol"] == "6"
    assert egress[3]["PortRange"] == {"From": 443, "To": 443}
    assert egress[4]["RuleAction"] == "deny"

    assert [entry["RuleNumber"] for entry in ingress] == [100, 110, 32766]
    assert ingress[0]["PortRange"] == {"From": 1024, "To": 65535}
    assert ingress[1]["PortRange"] == {"From": 1024, "To": 65535}
    assert ingress[2]["RuleAction"] == "deny"


def test_worker_management_does_not_require_imds_or_an_instance_profile() -> None:
    template = load_template()
    worker = template["Resources"]["WorkerInstance"]["Properties"]

    assert "WorkerInstanceProfileName" not in template["Parameters"]
    assert "IamInstanceProfile" not in worker
    assert worker["MetadataOptions"]["HttpEndpoint"] == "disabled"
    assert "amazon-ssm-agent" not in worker["UserData"]["Fn::Base64"]["Fn::Sub"][0].lower()
    bootstrap = worker["UserData"]["Fn::Base64"]["Fn::Sub"][0]
    assert "retrieve_with_ec2_get_console_output=true" in bootstrap
